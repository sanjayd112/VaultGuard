from helpers import PASSWORD, login, make_pdf, register, upload
from models import Incident, User, db


def test_register_new_user_hashes_with_argon2id(app, client):          # TEST 1
    r, code = register(client)
    assert r.status_code == 200 and code and len(code.replace("-", "")) == 16
    with app.app_context():
        u = User.query.filter_by(username="alice").first()
        assert u.password_hash.startswith("$argon2id$") and PASSWORD not in u.password_hash
        assert u.role == "user" and u.status == "active"


def test_register_rejects_weak_password_and_duplicates(client):
    r, code = register(client, password="short")
    assert code is None and b"at least 10" in r.data
    register(client)
    r, code = register(client)
    assert code is None and b"already registered" in r.data


def test_login_valid_credentials_and_dashboard(app, client):           # TEST 2
    register(client)
    r = login(client)
    assert r.status_code == 302
    assert client.get("/dashboard").status_code == 200
    with app.app_context():
        assert Incident.query.filter_by(event_type="login_success").count() == 1


def test_login_invalid_credentials(client):
    register(client)
    assert login(client, password="Wrong-Password1").status_code == 401
    assert client.get("/dashboard").status_code == 302          # still anonymous


def test_protected_pages_require_login(client):
    for url in ("/dashboard", "/files", "/upload", "/incidents", "/risk", "/admin"):
        r = client.get(url)
        assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_users_cannot_access_each_others_files(app):
    a, b = app.test_client(), app.test_client()
    register(a, "alice"); login(a, "alice"); register(b, "bob"); login(b, "bob")
    assert upload(a).get_json()["ok"]
    from models import File
    with app.app_context():
        pid = File.query.first().public_id
    assert b.get(f"/files/{pid}/download").status_code == 403
    assert b.get(f"/files/{pid}/versions").status_code == 403
    with app.app_context():
        assert Incident.query.filter_by(event_type="unauthorized_access").count() == 2
    assert a.get(f"/files/{pid}/download").status_code == 200       # the owner is unaffected


def test_logout_invalidates_session(client):
    register(client); login(client)
    assert client.post("/logout").status_code == 302
    assert client.get("/dashboard").status_code == 302
