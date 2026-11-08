"""Authentication security, risk scoring, account restriction and audit logging.

All enforcement is server-side: restricted accounts have their sessions revoked in the
database and every request re-validates the session token (see app.before_request).
"""
import re
import secrets
from datetime import timedelta

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from flask import current_app, has_request_context, request

from models import AccountSession, Incident, LoginAttempt, SecurityEvent, User, db, utcnow

# ---------------------------------------------------------------- passwords (Argon2id)
_ph = PasswordHasher(type=Type.ID)
_DUMMY_HASH = _ph.hash("vaultguard-timing-equaliser")


def hash_secret(value: str) -> str:
    return _ph.hash(value)


def verify_secret(stored_hash: str, value: str) -> bool:
    try:
        return _ph.verify(stored_hash, value)
    except (VerificationError, InvalidHashError):
        return False


def dummy_verify():
    """Burn comparable time for unknown usernames (prevents user enumeration by timing)."""
    verify_secret(_DUMMY_HASH, "x")


def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)


def generate_recovery_code():
    """Returns (display_code, normalized_code_to_hash). Shown once at registration."""
    raw = secrets.token_hex(8).upper()
    return "-".join(raw[i:i + 4] for i in range(0, 16, 4)), raw


def normalize_recovery_code(code: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", code or "").upper()


def valid_password(pw: str):
    """Returns an error message or None."""
    if len(pw) < 10:
        return "Password must be at least 10 characters."
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"\d", pw)):
        return "Password needs upper-case, lower-case and a number."
    return None


# ---------------------------------------------------------------- helpers
def client_ip():
    return (request.remote_addr or "unknown")[:64] if has_request_context() else "system"


def user_agent():
    return (request.headers.get("User-Agent", "")[:255]) if has_request_context() else ""


def risk_level(score: int) -> str:
    cfg = current_app.config
    if score <= cfg["RISK_LOW_MAX"]:
        return "Low"
    if score <= cfg["RISK_MEDIUM_MAX"]:
        return "Medium"
    return "High"


# ---------------------------------------------------------------- audit log
def log_incident(event_type, status="ok", details="", user=None, user_id=None,
                 file_public_id=None, commit=True):
    """Append a security audit record (status: ok | warning | critical)."""
    uid = user.id if user is not None else user_id
    inc = Incident(user_id=uid, event_type=event_type, status=status, details=(details or "")[:500],
                   file_public_id=file_public_id, ip_address=client_ip())
    db.session.add(inc)
    if commit:
        db.session.commit()
    return inc


def record_login_attempt(user, username_attempted, success):
    db.session.add(LoginAttempt(user_id=user.id if user else None, username_attempted=(username_attempted or "")[:80],
                                success=success, ip_address=client_ip(), user_agent=user_agent()))


# ---------------------------------------------------------------- sessions
def create_session(user) -> str:
    token = secrets.token_urlsafe(32)
    db.session.add(AccountSession(user_id=user.id, token=token, ip_address=client_ip(), user_agent=user_agent()))
    return token


def revoke_all_sessions(user, reason="revoked"):
    now = utcnow()
    n = 0
    for s in AccountSession.query.filter_by(user_id=user.id, revoked=False).all():
        s.revoked, s.revoked_at, s.revoke_reason = True, now, reason[:120]
        n += 1
    return n


# ---------------------------------------------------------------- risk scoring
def compute_risk_score(user) -> int:
    cfg = current_app.config
    since = utcnow() - timedelta(hours=cfg["RISK_WINDOW_HOURS"])
    total = (db.session.query(db.func.coalesce(db.func.sum(SecurityEvent.points), 0))
             .filter(SecurityEvent.user_id == user.id, SecurityEvent.cleared.is_(False),
                     SecurityEvent.created_at >= since).scalar())
    user.risk_score = max(0, min(100, int(total)))
    return user.risk_score


def active_risk_events(user):
    since = utcnow() - timedelta(hours=current_app.config["RISK_WINDOW_HOURS"])
    return (SecurityEvent.query.filter(SecurityEvent.user_id == user.id, SecurityEvent.cleared.is_(False),
                                       SecurityEvent.created_at >= since)
            .order_by(SecurityEvent.created_at.desc()).all())


def add_risk_event(user, event_type, details=""):
    """Add a scored event (points come from config). Call evaluate_risk() afterwards."""
    points = current_app.config["RISK_POINTS"][event_type]
    db.session.add(SecurityEvent(user_id=user.id, event_type=event_type, points=points, details=details[:300]))
    db.session.flush()
    return points


def evaluate_risk(user) -> bool:
    """Recompute the score; restrict the account when it reaches High. Returns True if restricted now."""
    score = compute_risk_score(user)
    restricted_now = False
    if score > current_app.config["RISK_MEDIUM_MAX"] \
            and user.status == "active" and not user.is_admin:
        restrict_account(user, f"Automatic restriction: risk score {score} (High)",
                         minutes=current_app.config["RESTRICTION_MINUTES"], commit=False)
        restricted_now = True
    db.session.commit()
    return restricted_now


def restrict_account(user, reason, minutes=None, commit=True, actor=None):
    user.status = "restricted"
    user.restriction_reason = reason[:255]
    user.restricted_until = utcnow() + timedelta(minutes=minutes) if minutes else None
    n = revoke_all_sessions(user, "account restricted")
    log_incident("account_restriction", "critical",
                 f"{reason}. {n} session(s) invalidated." + (f" Actor: {actor.username}." if actor else ""),
                 user=user, commit=False)
    if commit:
        db.session.commit()


def lift_restriction(user, method, clear_events=True, commit=True, actor=None):
    user.status = "active"
    user.restricted_until = None
    user.restriction_reason = None
    user.failed_login_count = 0
    if clear_events:
        for ev in SecurityEvent.query.filter_by(user_id=user.id, cleared=False).all():
            ev.cleared = True
    compute_risk_score(user)
    log_incident("account_verification", "ok",
                 f"Account reactivated via {method}." + (f" Actor: {actor.username}." if actor else ""),
                 user=user, commit=False)
    if commit:
        db.session.commit()


def refresh_restriction(user):
    """Temporary restrictions expire; the risk events stay, so one more failure re-restricts."""
    if user.status == "restricted" and user.restricted_until and utcnow() >= user.restricted_until:
        user.status = "active"
        user.restricted_until = None
        user.restriction_reason = None
        log_incident("account_verification", "warning",
                     "Temporary restriction expired; account re-enabled under heightened risk.", user=user, commit=False)
        db.session.commit()


def handle_failed_login(user, details="Invalid password"):
    """Track failures and score them. Returns True if the account just got restricted."""
    cfg = current_app.config
    now = utcnow()
    if user.last_failed_login_at is None or now - user.last_failed_login_at > timedelta(minutes=cfg["FAILURE_WINDOW_MINUTES"]):
        user.failed_login_count = 0
    user.failed_login_count += 1
    user.last_failed_login_at = now
    add_risk_event(user, "failed_login", f"{details} (attempt {user.failed_login_count})")
    if user.failed_login_count >= cfg["REPEATED_FAILURE_THRESHOLD"]:
        add_risk_event(user, "repeated_failed_login",
                       f"{user.failed_login_count} consecutive failures within {cfg['FAILURE_WINDOW_MINUTES']} min")
    log_incident("failed_login", "warning", f"{details} (attempt {user.failed_login_count})", user=user, commit=False)
    return evaluate_risk(user)
