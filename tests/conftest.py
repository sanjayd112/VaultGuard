import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app          # noqa: E402
from encryption import generate_key  # noqa: E402
from models import db                # noqa: E402


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True, "SECRET_KEY": "test-secret", "ENCRYPTION_KEY": generate_key(),
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}", "STORAGE_DIR": tmp_path / "enc",
        "WTF_CSRF_ENABLED": False, "SESSION_COOKIE_SECURE": False, "MAX_UPLOAD_MB": 1,
    })
    yield application
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()
