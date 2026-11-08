"""VaultGuard configuration. Secrets come from environment variables only."""
import os
from datetime import timedelta
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:  # python-dotenv is optional
    pass

BASE_DIR = Path(__file__).resolve().parent


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# extension -> acceptable declared MIME types
ALLOWED_TYPES = {
    "pdf": {"application/pdf"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "txt": {"text/plain"},
    "png": {"image/png"},
    "jpg": {"image/jpeg", "image/pjpeg"},
    "jpeg": {"image/jpeg", "image/pjpeg"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
}
# Browsers sometimes send these for valid files; content (magic bytes) is still checked.
GENERIC_MIME = {"", "application/octet-stream"}


class Config:
    APP_ENV = os.environ.get("VAULTGUARD_ENV", "development")
    IS_PRODUCTION = APP_ENV == "production"

    # --- secrets (never hardcoded) ---
    SECRET_KEY = os.environ.get("SECRET_KEY") or None
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY") or None

    # --- database / storage ---
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///" + str(BASE_DIR / "vaultguard.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    STORAGE_DIR = Path(os.environ.get("STORAGE_DIR") or BASE_DIR / "storage" / "encrypted_files")

    # --- uploads ---
    MAX_UPLOAD_MB = _int("MAX_UPLOAD_MB", 16)
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024 + 64 * 1024  # + multipart overhead

    # --- sessions / cookies / CSRF ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_int("SESSION_MINUTES", 30))
    WTF_CSRF_TIME_LIMIT = None  # token lives as long as the session

    # --- risk scoring (fully configurable) ---
    RISK_POINTS = {
        "failed_login": 10,
        "repeated_failed_login": 20,       # added on top once the threshold is reached
        "unauthorized_file_access": 25,
        "invalid_recovery_request": 20,
        "integrity_failure": 15,
        "failed_identity_verification": 10,
    }
    RISK_LOW_MAX = 29        # 0-29 Low
    RISK_MEDIUM_MAX = 59     # 30-59 Medium, 60-100 High
    RISK_WINDOW_HOURS = _int("RISK_WINDOW_HOURS", 24)       # events older than this stop counting
    REPEATED_FAILURE_THRESHOLD = 3
    FAILURE_WINDOW_MINUTES = 15
    RESTRICTION_MINUTES = _int("RESTRICTION_MINUTES", 15)
