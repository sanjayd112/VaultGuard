"""VaultGuard - Secure File Storage and Intelligent Threat Protection System."""
import re
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

import click
from flask import (Flask, abort, flash, jsonify, redirect, render_template, request, send_file,
                   session, url_for)
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy import func, or_

from config import ALLOWED_TYPES, Config
from encryption import ConfigurationError, generate_key, load_key
from file_service import REASONS, UploadError, check_version, create_file, create_version, validate_upload
from models import AccountSession, File, FileVersion, Incident, LoginAttempt, SecurityEvent, User, db, utcnow
from recovery import restore_version
from security import (active_risk_events, add_risk_event, compute_risk_score, create_session, dummy_verify,
                      evaluate_risk, generate_recovery_code, handle_failed_login, hash_secret, lift_restriction,
                      log_incident, needs_rehash, normalize_recovery_code, record_login_attempt, refresh_restriction,
                      restrict_account, revoke_all_sessions, risk_level, valid_password, verify_secret)

csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"

EVENT_LABELS = {
    "login_success": "Successful login", "failed_login": "Failed login", "user_registered": "Account registered",
    "logout": "Logout", "file_upload": "File upload", "file_encryption": "File encryption",
    "file_download": "File download", "integrity_verification": "Integrity verification",
    "tampering_detected": "Tampering detected", "unauthorized_access": "Unauthorized access",
    "account_restriction": "Account restriction", "account_verification": "Account verification",
    "version_restored": "Version restored", "recovery_rejected": "Recovery rejected",
    "upload_rejected": "Upload rejected", "verification_failed": "Identity verification failed",
    "session_revoked": "Sessions revoked",
}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        app.logger.warning("SECRET_KEY not set: using a temporary key (sessions reset on restart).")
    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    with app.app_context():
        db.create_all()

    register_filters(app)
    register_hooks(app)
    register_routes(app)
    register_cli(app)
    return app


# ====================================================================== helpers
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def register_filters(app):
    @app.template_filter("dt")
    def dt(v):
        return v.strftime("%d %b %Y, %H:%M") if v else "-"

    @app.template_filter("filesize")
    def filesize(n):
        n = float(n or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024

    @app.template_filter("event_label")
    def event_label(v):
        return EVENT_LABELS.get(v, v.replace("_", " ").title())

    app.jinja_env.globals["risk_level"] = risk_level
    app.jinja_env.globals["EVENT_LABELS"] = EVENT_LABELS


def restriction_response():
    """Immediately end the session of a user who just got restricted."""
    logout_user()
    session.clear()
    flash("Your account was temporarily restricted because of suspicious activity. Verify your identity to reactivate it.", "danger")
    return redirect(url_for("verify_identity"))


def owned_file_or_deny(public_id):
    """Server-side ownership check. Another user's file => 403 + incident + risk points."""
    f = File.query.filter_by(public_id=public_id).first()
    if f is None:
        abort(404)
    if f.owner_id != current_user.id:
        add_risk_event(current_user, "unauthorized_file_access", f"Tried to access file {public_id}")
        log_incident("unauthorized_access", "critical", f"Attempted access to a file owned by another user ({public_id}).",
                     user=current_user, file_public_id=public_id, commit=False)
        if evaluate_risk(current_user):
            abort(restriction_response())
        abort(403)
    return f


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            add_risk_event(current_user, "unauthorized_file_access", "Attempted to open the admin area")
            log_incident("unauthorized_access", "critical", "Non-admin attempted to open the administrator area.",
                         user=current_user, commit=False)
            if evaluate_risk(current_user):
                abort(restriction_response())
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def find_user(identifier):
    ident = (identifier or "").strip().lower()
    if not ident:
        return None
    return User.query.filter(or_(func.lower(User.username) == ident, func.lower(User.email) == ident)).first()


def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") and "\\" not in target else None


# ====================================================================== hooks
def register_hooks(app):
    @app.before_request
    def guard():
        if request.endpoint == "static":
            return None
        try:  # stop securely if the encryption key is absent
            load_key(app.config.get("ENCRYPTION_KEY"))
        except ConfigurationError as exc:
            return render_template("error.html", code=503, title="Configuration error", message=str(exc)), 503
        if current_user.is_authenticated:
            token = session.get("vg_token")
            sess = (AccountSession.query.filter_by(token=token, user_id=current_user.id, revoked=False).first()
                    if token else None)
            if sess is None or current_user.status != "active":
                logout_user()
                session.clear()
                flash("Your session is no longer valid. Please sign in again.", "warning")
                return redirect(url_for("login"))
            now = utcnow()
            if now - sess.last_seen_at > timedelta(minutes=1):
                sess.last_seen_at = now
                db.session.commit()
        return None

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; img-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def error_page(code, title, message):
        if request.path == "/upload" and request.method == "POST":
            return jsonify(ok=False, error=message), code
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(403)
    def e403(e):
        return error_page(403, "Access denied", "You do not have permission to access this resource. The attempt was recorded.")

    @app.errorhandler(404)
    def e404(e):
        return error_page(404, "Not found", "The page or file you requested does not exist.")

    @app.errorhandler(413)
    def e413(e):
        return error_page(413, "File too large", f"Uploads are limited to {app.config['MAX_UPLOAD_MB']} MB.")

    @app.errorhandler(CSRFError)
    def ecsrf(e):
        return error_page(400, "Security token expired", "Your form session expired or the CSRF token was invalid. Reload the page and try again.")

    @app.errorhandler(ConfigurationError)
    def econf(e):
        return error_page(503, "Configuration error", str(e))

    @app.errorhandler(500)
    def e500(e):
        db.session.rollback()
        return error_page(500, "Something went wrong", "An internal error occurred. No sensitive details are shown.")


# ====================================================================== dashboards data
def user_stats(user):
    files = File.query.filter_by(owner_id=user.id).all()
    versions = FileVersion.query.join(File).filter(File.owner_id == user.id).all()
    current = [f.current for f in files if f.current]
    incidents = Incident.query.filter(Incident.user_id == user.id)
    return {
        "total_files": len(files),
        "encrypted_files": len(versions),
        "storage_bytes": sum(v.encrypted_size for v in versions),
        "risk_score": compute_risk_score(user),
        "verified": sum(1 for v in current if v.integrity_status == "verified"),
        "failed": sum(1 for v in current if v.integrity_status == "failed"),
        "unverified": sum(1 for v in current if v.integrity_status == "unverified"),
        "incidents": incidents.filter(Incident.status != "ok").count(),
        "versions": versions,
        "files": files,
    }


def activity_series(query, days=7):
    start = (utcnow() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    labels = [(start + timedelta(days=i)) for i in range(days)]
    ok, bad = defaultdict(int), defaultdict(int)
    for inc in query.filter(Incident.created_at >= start).all():
        (ok if inc.status == "ok" else bad)[inc.created_at.date()] += 1
    return {"labels": [d.strftime("%d %b") for d in labels],
            "normal": [ok[d.date()] for d in labels], "alerts": [bad[d.date()] for d in labels]}


# ====================================================================== routes
def register_routes(app):
    # ------------------------------------------------------------ public / auth
    @app.route("/")
    def index():
        return redirect(url_for("dashboard") if current_user.is_authenticated else url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        form = {"username": "", "email": ""}
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
            form = {"username": username, "email": email}
            error = None
            if not USERNAME_RE.match(username):
                error = "Username must be 3-30 characters: letters, numbers, dot, dash or underscore."
            elif not EMAIL_RE.match(email) or len(email) > 120:
                error = "Enter a valid email address."
            elif pw != pw2:
                error = "Passwords do not match."
            else:
                error = valid_password(pw)
            if not error and User.query.filter(or_(func.lower(User.username) == username.lower(), User.email == email)).first():
                error = "That username or email is already registered."
            if error:
                flash(error, "danger")
            else:
                display, normalized = generate_recovery_code()
                user = User(username=username, email=email, password_hash=hash_secret(pw),
                            recovery_code_hash=hash_secret(normalized))
                db.session.add(user)
                db.session.flush()
                log_incident("user_registered", "ok", "New account created.", user=user, commit=False)
                db.session.commit()
                return render_template("register.html", form=form, recovery_code=display, new_user=username)
        return render_template("register.html", form=form, recovery_code=None)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            ident = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = find_user(ident)
            if user is None or user.status == "disabled":
                dummy_verify()
                record_login_attempt(None, ident, False)
                log_incident("failed_login", "warning", f"Login attempt for unknown account '{ident[:40]}'.")
                flash("Invalid username or password.", "danger")
                return render_template("login.html"), 401

            refresh_restriction(user)
            if user.status == "restricted":
                record_login_attempt(user, ident, False)
                log_incident("failed_login", "warning", "Login blocked: account is restricted.", user=user)
                flash("This account is temporarily restricted. Verify your identity to reactivate it.", "danger")
                return redirect(url_for("verify_identity"))

            if not verify_secret(user.password_hash, password):
                record_login_attempt(user, ident, False)
                restricted = handle_failed_login(user)
                if restricted:
                    flash("Too many suspicious attempts. The account has been temporarily restricted. Verify your identity to reactivate it.", "danger")
                    return redirect(url_for("verify_identity"))
                flash("Invalid username or password.", "danger")
                return render_template("login.html"), 401

            # success: fresh session (prevents session fixation)
            session.clear()
            login_user(user)
            session["vg_token"] = create_session(user)
            session.permanent = True
            if needs_rehash(user.password_hash):
                user.password_hash = hash_secret(password)
            user.failed_login_count = 0
            user.last_login_at = utcnow()
            record_login_attempt(user, ident, True)
            log_incident("login_success", "ok", "Signed in.", user=user, commit=False)
            db.session.commit()
            return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        sess = AccountSession.query.filter_by(token=session.get("vg_token"), user_id=current_user.id).first()
        if sess:
            sess.revoked, sess.revoked_at, sess.revoke_reason = True, utcnow(), "logout"
        log_incident("logout", "ok", "Signed out.", user=current_user)
        logout_user()
        session.clear()
        flash("You have been signed out.", "info")
        return redirect(url_for("login"))

    @app.route("/verify-identity", methods=["GET", "POST"])
    def verify_identity():
        if request.method == "POST":
            ident = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            code = normalize_recovery_code(request.form.get("recovery_code", ""))
            user = find_user(ident)
            if user is None:
                dummy_verify()
                dummy_verify()
                flash("Verification failed. Check your details and try again.", "danger")
                return render_template("login.html", verify=True), 400
            pw_ok = verify_secret(user.password_hash, password)
            code_ok = verify_secret(user.recovery_code_hash, code)   # both always evaluated
            if not (pw_ok and code_ok):
                add_risk_event(user, "failed_identity_verification", "Wrong password or recovery code")
                log_incident("verification_failed", "warning", "Identity verification failed.", user=user, commit=False)
                evaluate_risk(user)
                flash("Verification failed. Check your details and try again.", "danger")
                return render_template("login.html", verify=True), 400
            refresh_restriction(user)
            if user.status == "restricted":
                lift_restriction(user, "identity verification (password + recovery code)")
                flash("Identity verified. Your account is active again - please sign in.", "success")
            else:
                flash("This account is not restricted. You can sign in.", "info")
            return redirect(url_for("login"))
        return render_template("login.html", verify=True)

    # ------------------------------------------------------------ dashboard
    @app.route("/dashboard")
    @login_required
    def dashboard():
        s = user_stats(current_user)
        db.session.commit()
        incidents_q = Incident.query.filter_by(user_id=current_user.id)
        recent_incidents = incidents_q.order_by(Incident.created_at.desc()).limit(6).all()
        alerts = incidents_q.filter(Incident.status != "ok").order_by(Incident.created_at.desc()).limit(5).all()
        recent_files = sorted(s["files"], key=lambda f: f.updated_at, reverse=True)[:5]
        risk_by_type = defaultdict(int)
        for ev in active_risk_events(current_user):
            risk_by_type[ev.event_type] += ev.points
        storage_by_ext = defaultdict(int)
        for v in s["versions"]:
            storage_by_ext[v.file.extension.upper()] += v.encrypted_size
        chart_data = {
            "activity": activity_series(incidents_q),
            "risk": {"labels": [k.replace("_", " ").title() for k in risk_by_type], "values": list(risk_by_type.values())},
            "storage": {"labels": list(storage_by_ext), "values": [round(b / 1024, 1) for b in storage_by_ext.values()]},
        }
        active_sessions = AccountSession.query.filter_by(user_id=current_user.id, revoked=False).count()
        return render_template("dashboard.html", s=s, level=risk_level(s["risk_score"]), recent_files=recent_files,
                               recent_incidents=recent_incidents, alerts=alerts, chart_data=chart_data, active_sessions=active_sessions)

    # ------------------------------------------------------------ files
    @app.route("/files")
    @login_required
    def files():
        q = request.args.get("q", "").strip()
        query = File.query.filter_by(owner_id=current_user.id)
        if q:
            query = query.filter(File.original_name.ilike(f"%{q}%"))
        return render_template("files.html", files=query.order_by(File.updated_at.desc()).all(), q=q)

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        my_files = File.query.filter_by(owner_id=current_user.id).order_by(File.original_name).all()
        if request.method == "GET":
            return render_template("upload.html", files=my_files, preselect=request.args.get("file", ""),
                                   allowed=[e.upper() for e in ALLOWED_TYPES])
        target_id = request.form.get("target_file_id", "").strip()
        try:
            name, ext, mime, data = validate_upload(request.files.get("file"))
            if target_id:
                f = owned_file_or_deny(target_id)
                if ext != f.extension:
                    raise UploadError(f"A new version must be a .{f.extension} file (you sent .{ext}).")
                version = create_version(f, data)
            else:
                f = create_file(current_user, name, ext, mime, data)
                version = f.current
            ok = version.integrity_status == "verified"
            log_incident("file_upload", "ok", f"Uploaded {f.original_name} v{version.version_number} ({len(data)} bytes).",
                         user=current_user, file_public_id=f.public_id, commit=False)
            log_incident("file_encryption", "ok" if ok else "critical",
                         f"{f.original_name} v{version.version_number} encrypted with AES-256-GCM; SHA-256 {version.plaintext_sha256[:16]}...",
                         user=current_user, file_public_id=f.public_id, commit=False)
            db.session.commit()
        except UploadError as exc:
            db.session.rollback()
            log_incident("upload_rejected", "warning", str(exc), user=current_user)
            return jsonify(ok=False, error=str(exc)), 400
        return jsonify(ok=True, message="File encrypted with AES-256-GCM and stored securely.", filename=f.original_name,
                       version=version.version_number, size=version.size_bytes, encrypted_size=version.encrypted_size,
                       sha256=version.plaintext_sha256, nonce=version.nonce_hex, integrity=version.integrity_status,
                       files_url=url_for("files"))

    @app.route("/files/<public_id>/download")
    @login_required
    def download(public_id):
        f = owned_file_or_deny(public_id)
        number = request.args.get("version", type=int) or f.current_version
        v = f.version(number) or abort(404)
        result = check_version(v, current_user, action="download")
        if not result.ok:   # never return corrupted content
            if current_user.status != "active":
                return restriction_response()
            flash("Download blocked: integrity verification failed for this file. The incident was recorded.", "danger")
            return redirect(url_for("versions", public_id=public_id))
        log_incident("file_download", "ok", f"Downloaded {f.original_name} v{v.version_number}.",
                     user=current_user, file_public_id=public_id)
        name = f.original_name if v.version_number == f.current_version else \
            f"{f.original_name.rsplit('.', 1)[0]}_v{v.version_number}.{f.extension}"
        return send_file(BytesIO(result.plaintext), mimetype=f.mime_type, as_attachment=True, download_name=name)

    @app.route("/files/<public_id>/verify", methods=["POST"])
    @login_required
    def verify_file(public_id):
        f = owned_file_or_deny(public_id)
        number = request.form.get("version", type=int) or f.current_version
        v = f.version(number) or abort(404)
        result = check_version(v, current_user, action="verify")
        if current_user.status != "active":
            return restriction_response()
        if result.ok:
            flash(f"Integrity verified: {f.original_name} v{v.version_number} passed AES-GCM authentication and SHA-256 checks.", "success")
        else:
            flash(f"INTEGRITY FAILURE: {f.original_name} v{v.version_number} - " + REASONS[result.reason] +
                  " Content was not decrypted and a security incident was recorded.", "danger")
        return redirect(url_for("versions", public_id=public_id) if request.form.get("back") == "versions" else url_for("files"))

    @app.route("/files/<public_id>/versions")
    @login_required
    def versions(public_id):
        f = owned_file_or_deny(public_id)
        history = (Incident.query.filter(Incident.file_public_id == public_id,
                                         Incident.event_type.in_(["integrity_verification", "tampering_detected", "version_restored", "recovery_rejected"]))
                   .order_by(Incident.created_at.desc()).limit(10).all())
        return render_template("versions.html", file=f, versions=list(reversed(f.versions)), history=history)

    @app.route("/files/<public_id>/restore/<int:number>", methods=["POST"])
    @login_required
    def restore(public_id, number):
        f = owned_file_or_deny(public_id)
        result = restore_version(f, number, current_user)
        if current_user.status != "active":
            return restriction_response()
        flash(result.message, "success" if result.ok else "danger")
        return redirect(url_for("versions", public_id=public_id))

    # ------------------------------------------------------------ incidents / risk
    @app.route("/incidents")
    @login_required
    def incidents():
        q = request.args.get("q", "").strip()
        etype = request.args.get("event_type", "")
        status = request.args.get("status", "")
        d_from, d_to = request.args.get("date_from", ""), request.args.get("date_to", "")
        query = db.session.query(Incident).outerjoin(User, Incident.user_id == User.id)
        if not current_user.is_admin:
            query = query.filter(Incident.user_id == current_user.id)
        if q:
            like = f"%{q}%"
            query = query.filter(or_(Incident.details.ilike(like), Incident.event_type.ilike(like),
                                     User.username.ilike(like), Incident.ip_address.ilike(like)))
        if etype in EVENT_LABELS:
            query = query.filter(Incident.event_type == etype)
        if status in ("ok", "warning", "critical"):
            query = query.filter(Incident.status == status)
        try:
            if d_from:
                query = query.filter(Incident.created_at >= datetime.strptime(d_from, "%Y-%m-%d"))
            if d_to:
                query = query.filter(Incident.created_at < datetime.strptime(d_to, "%Y-%m-%d") + timedelta(days=1))
        except ValueError:
            flash("Dates must use the YYYY-MM-DD format.", "warning")
        page = request.args.get("page", 1, type=int)
        pagination = query.order_by(Incident.created_at.desc(), Incident.id.desc()).paginate(page=page, per_page=15, error_out=False)
        filters = {"q": q, "event_type": etype, "status": status, "date_from": d_from, "date_to": d_to}
        return render_template("incidents.html", pagination=pagination, filters=filters)

    @app.route("/risk")
    @login_required
    def risk_monitor():
        score = compute_risk_score(current_user)
        db.session.commit()
        events = active_risk_events(current_user)
        by_type = defaultdict(int)
        for ev in events:
            by_type[ev.event_type] += ev.points
        history = (Incident.query.filter(Incident.user_id == current_user.id,
                                         Incident.event_type.in_(["account_restriction", "account_verification"]))
                   .order_by(Incident.created_at.desc()).limit(8).all())
        sessions = (AccountSession.query.filter_by(user_id=current_user.id, revoked=False)
                    .order_by(AccountSession.last_seen_at.desc()).all())
        attempts = LoginAttempt.query.filter_by(user_id=current_user.id).order_by(LoginAttempt.created_at.desc()).limit(8).all()
        chart_data = {"score": score, "labels": [k.replace("_", " ").title() for k in by_type], "values": list(by_type.values())}
        return render_template("risk_monitor.html", score=score, level=risk_level(score), events=events, history=history,
                               sessions=sessions, attempts=attempts, chart_data=chart_data, current_token=session.get("vg_token"))

    # ------------------------------------------------------------ admin
    @app.route("/admin")
    @admin_required
    def admin():
        users = User.query.order_by(User.created_at).all()
        for u in users:
            compute_risk_score(u)
        db.session.commit()
        file_counts = dict(db.session.query(File.owner_id, func.count(File.id)).group_by(File.owner_id).all())
        levels = {"Low": 0, "Medium": 0, "High": 0}
        for u in users:
            levels[risk_level(u.risk_score)] += 1
        by_type = dict(db.session.query(Incident.event_type, func.count(Incident.id)).group_by(Incident.event_type)
                       .order_by(func.count(Incident.id).desc()).limit(8).all())
        recent = lambda types, n=8: (Incident.query.filter(Incident.event_type.in_(types))
                                     .order_by(Incident.created_at.desc()).limit(n).all())
        stats = {
            "users": len(users), "files": File.query.count(), "versions": FileVersion.query.count(),
            "restricted": sum(1 for u in users if u.status == "restricted"),
            "high_risk": levels["High"], "integrity_failures": Incident.query.filter_by(event_type="tampering_detected").count(),
            "incidents": Incident.query.count(),
            "storage": db.session.query(func.coalesce(func.sum(FileVersion.encrypted_size), 0)).scalar(),
        }
        chart_data = {"levels": levels, "events": {"labels": [EVENT_LABELS.get(k, k) for k in by_type], "values": list(by_type.values())},
                      "activity": activity_series(Incident.query)}
        return render_template("admin.html", users=users, file_counts=file_counts, stats=stats, chart_data=chart_data,
                               restricted=[u for u in users if u.status == "restricted"],
                               integrity=recent(["tampering_detected"]), recoveries=recent(["version_restored", "recovery_rejected"]),
                               recent=Incident.query.order_by(Incident.created_at.desc()).limit(10).all())

    @app.route("/admin/users/<int:user_id>/<action>", methods=["POST"])
    @admin_required
    def admin_user_action(user_id, action):
        target = db.session.get(User, user_id) or abort(404)
        if action == "restrict":
            if target.is_admin:
                flash("Administrator accounts cannot be restricted.", "warning")
            else:
                restrict_account(target, f"Restricted by administrator {current_user.username}", actor=current_user)
                flash(f"{target.username} has been restricted and their sessions invalidated.", "success")
        elif action == "unrestrict":
            lift_restriction(target, "administrator review", actor=current_user)
            flash(f"{target.username} has been reactivated.", "success")
        elif action == "revoke-sessions":
            n = revoke_all_sessions(target, "revoked by administrator")
            log_incident("session_revoked", "warning", f"Administrator {current_user.username} revoked {n} session(s).", user=target)
            flash(f"Revoked {n} active session(s) for {target.username}.", "success")
        else:
            abort(400)
        return redirect(url_for("admin"))


# ====================================================================== CLI
def register_cli(app):
    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--email", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin(username, email, password):
        """Create an administrator account."""
        err = (None if USERNAME_RE.match(username) else "Invalid username") or \
              (None if EMAIL_RE.match(email) else "Invalid email") or valid_password(password)
        if err:
            raise click.ClickException(err)
        if User.query.filter(or_(func.lower(User.username) == username.lower(), User.email == email.lower())).first():
            raise click.ClickException("User already exists.")
        display, normalized = generate_recovery_code()
        db.session.add(User(username=username, email=email.lower(), role="admin", password_hash=hash_secret(password),
                            recovery_code_hash=hash_secret(normalized)))
        db.session.commit()
        click.echo(f"Admin '{username}' created.\nRecovery code (store it safely, shown once): {display}")

    @app.cli.command("generate-key")
    def gen_key():
        """Print a new random 256-bit encryption key."""
        click.echo(generate_key())


if __name__ == "__main__":
    application = create_app()
    application.run(host="127.0.0.1", port=5000, debug=not Config.IS_PRODUCTION)
