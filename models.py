"""SQLAlchemy models: users, files, file_versions, incidents, login_attempts,
account_sessions, security_events."""
from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    """Naive UTC timestamp (SQLite friendly)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)          # Argon2id
    recovery_code_hash = db.Column(db.String(255), nullable=False)     # Argon2id (identity verification)
    role = db.Column(db.String(10), nullable=False, default="user")    # 'user' | 'admin'
    status = db.Column(db.String(12), nullable=False, default="active")  # active | restricted | disabled
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    restricted_until = db.Column(db.DateTime)          # None + status restricted = until verified/admin lifts
    restriction_reason = db.Column(db.String(255))
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    last_failed_login_at = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    files = db.relationship("File", back_populates="owner", cascade="all, delete-orphan")
    incidents = db.relationship("Incident", back_populates="user")
    sessions = db.relationship("AccountSession", back_populates="user", cascade="all, delete-orphan")
    security_events = db.relationship("SecurityEvent", back_populates="user", cascade="all, delete-orphan")

    @property
    def is_admin(self):
        return self.role == "admin"

    @property
    def is_active(self):  # Flask-Login
        return self.status != "disabled"


class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(32), unique=True, nullable=False, index=True)  # random id used in URLs
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    extension = db.Column(db.String(10), nullable=False)
    mime_type = db.Column(db.String(120), nullable=False)
    current_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    owner = db.relationship("User", back_populates="files")
    versions = db.relationship("FileVersion", back_populates="file", cascade="all, delete-orphan",
                               order_by="FileVersion.version_number")

    @property
    def current(self):
        for v in self.versions:
            if v.version_number == self.current_version:
                return v
        return None

    def version(self, number):
        for v in self.versions:
            if v.version_number == number:
                return v
        return None


class FileVersion(db.Model):
    __tablename__ = "file_versions"
    __table_args__ = (db.UniqueConstraint("file_id", "version_number", name="uq_file_version"),)
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("files.id"), nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    stored_name = db.Column(db.String(64), unique=True, nullable=False)       # random id, never user input
    size_bytes = db.Column(db.Integer, nullable=False)                        # original size
    encrypted_size = db.Column(db.Integer, nullable=False)
    ciphertext_sha256 = db.Column(db.String(64), nullable=False)
    plaintext_sha256 = db.Column(db.String(64), nullable=False)
    nonce_hex = db.Column(db.String(24), unique=True, nullable=False)         # DB-enforced nonce uniqueness
    integrity_status = db.Column(db.String(12), nullable=False, default="unverified")  # verified|failed|unverified
    last_verified_at = db.Column(db.DateTime)
    restored_from = db.Column(db.Integer)                                     # source version when restored
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    file = db.relationship("File", back_populates="versions")


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    event_type = db.Column(db.String(40), nullable=False, index=True)
    status = db.Column(db.String(10), nullable=False, default="ok")  # ok | warning | critical
    details = db.Column(db.String(500), default="")
    file_public_id = db.Column(db.String(32))
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User", back_populates="incidents")


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    username_attempted = db.Column(db.String(80))
    success = db.Column(db.Boolean, nullable=False, default=False)
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class AccountSession(db.Model):
    __tablename__ = "account_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    revoked_at = db.Column(db.DateTime)
    revoke_reason = db.Column(db.String(120))

    user = db.relationship("User", back_populates="sessions")


class SecurityEvent(db.Model):
    """A risk-scoring event. The user's risk score = sum of uncleared, in-window points."""
    __tablename__ = "security_events"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    event_type = db.Column(db.String(40), nullable=False)
    points = db.Column(db.Integer, nullable=False)
    details = db.Column(db.String(300), default="")
    cleared = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    user = db.relationship("User", back_populates="security_events")
