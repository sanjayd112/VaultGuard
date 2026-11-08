import re

import pytest

from helpers import PASSWORD, login, make_admin, make_pdf, register, upload
from models import AccountSession, Incident, SecurityEvent, User, db, utcnow
from security import compute_risk_score, risk_level


def fail_login(client, n, user="alice"):
    for _ in range(n):
        client.post("/login", data={"username": user, "password": "Wrong-Password-1"})


def test_failed_logins_are_scored(app, client):                       # TEST 11
    register(client)
    fail_login(client, 1)
    with app.app_context():
        u = User.query.filter_by(username="alice").one()
        assert compute_risk_score(u) == 10 and risk_level(10) == "Low"
    fail_login(client, 2)                                              # 3rd failure adds the "repeated" +20
    with app.app_context():
        u = User.query.filter_by(username="alice").one()
        assert compute_risk_score(u) == 10 + 10 + 10 + 20 == 50 and risk_level(50) == "Medium"
        assert SecurityEvent.query.filter_by(event_type="repeated_failed_login").count() == 1
        assert Incident.query.filter_by(event_type="failed_login").count() == 3


def test_risk_classification_boundaries(app):
    with app.app_context():
        assert [risk_level(s) for s in (0, 29, 30, 59, 60, 100)] == ["Low", "Low", "Medium", "Medium", "High", "High"]


def test_high_risk_restricts_account_server_side(app, client):        # TEST 12
    register(client)
    fail_login(client, 4)
    with app.app_context():
        u = User.query.filter_by(username="alice").one()
        assert u.risk_score >= 60 and u.status == "restricted" and u.restricted_until is not None
        assert Incident.query.filter_by(event_type="account_restriction").count() == 1
    r = login(client)                                                  # even the CORRECT password is refused
    assert r.status_code == 302 and "verify-identity" in r.headers["Location"]
    assert client.get("/dashboard").status_code == 302


def test_restriction_invalidates_existing_sessions(app):
    a, attacker = app.test_client(), app.test_client()
    register(a); login(a)
    assert a.get("/dashboard").status_code == 200
    fail_login(attacker, 4)                                            # attacker triggers lock from another client
    r = a.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    with app.app_context():
        assert AccountSession.query.filter_by(revoked=False).count() == 0


def test_unauthorized_file_access_adds_25_points(app):
    a, b = app.test_client(), app.test_client()
    register(a, "alice"); login(a, "alice"); register(b, "bob"); login(b, "bob")
    upload(a)
    from models import File
    with app.app_context():
        pid = File.query.one().public_id
    assert b.get(f"/files/{pid}/download").status_code == 403
    with app.app_context():
        assert SecurityEvent.query.filter_by(event_type="unauthorized_file_access").one().points == 25
    b.get(f"/files/{pid}/download"); r = b.get(f"/files/{pid}/download")   # 3 x 25 = 75 -> High -> restricted
    with app.app_context():
        assert User.query.filter_by(username="bob").one().status == "restricted"
    assert r.status_code == 302


def test_identity_verification_reactivates_account(app, client):
    _, code = register(client)
    fail_login(client, 4)
    wrong = client.post("/verify-identity", data={"username": "alice", "password": PASSWORD, "recovery_code": "0000-0000-0000-0000"})
    assert wrong.status_code == 400
    ok = client.post("/verify-identity", data={"username": "alice", "password": PASSWORD, "recovery_code": code}, follow_redirects=True)
    assert b"Identity verified" in ok.data
    with app.app_context():
        u = User.query.filter_by(username="alice").one()
        assert u.status == "active" and compute_risk_score(u) == 0
        assert Incident.query.filter_by(event_type="account_verification").count() == 1
    assert login(client).status_code == 302 and client.get("/dashboard").status_code == 200


def test_temporary_restriction_expires(app, client):
    register(client); fail_login(client, 4)
    with app.app_context():
        u = User.query.filter_by(username="alice").one()
        u.restricted_until = utcnow().replace(microsecond=0) - __import__("datetime").timedelta(seconds=1); db.session.commit()
    assert login(client).status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_admin_can_view_incidents_and_manage_restrictions(app):       # TEST 13
    make_admin(app)
    admin, user = app.test_client(), app.test_client()
    register(user); fail_login(user, 4)
    login(admin, "admin")
    r = admin.get("/admin")
    assert r.status_code == 200 and b"alice" in r.data and b"Restricted" in r.data and b"Account restriction" in r.data
    inc = admin.get("/incidents")
    assert inc.status_code == 200 and b"alice" in inc.data and b"Failed login" in inc.data
    assert b"alice" in admin.get("/incidents?q=alice&event_type=failed_login&status=warning").data
    with app.app_context():
        uid = User.query.filter_by(username="alice").one().id
    admin.post(f"/admin/users/{uid}/unrestrict")
    with app.app_context():
        assert db.session.get(User, uid).status == "active"
    admin.post(f"/admin/users/{uid}/restrict")
    with app.app_context():
        assert db.session.get(User, uid).status == "restricted"


def test_non_admin_cannot_use_admin_area(app):
    make_admin(app)
    user = app.test_client(); register(user); login(user)
    assert user.get("/admin").status_code == 403
    with app.app_context():
        uid = User.query.filter_by(username="alice").one().id
    assert user.post(f"/admin/users/{uid}/restrict").status_code == 403
    with app.app_context():
        assert Incident.query.filter_by(event_type="unauthorized_access").count() == 2


def test_incident_page_only_shows_own_records_for_users(app):
    a, b = app.test_client(), app.test_client()
    register(a, "alice"); login(a, "alice"); register(b, "bob"); login(b, "bob")
    page = a.get("/incidents").data
    assert b"alice" in page and b"bob" not in page


def test_csrf_is_enforced_when_enabled(tmp_path):
    from app import create_app
    from encryption import generate_key
    app = create_app({"TESTING": True, "SECRET_KEY": "k", "ENCRYPTION_KEY": generate_key(),
                      "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'c.db'}", "STORAGE_DIR": tmp_path / "e"})
    r = app.test_client().post("/login", data={"username": "a", "password": "b"})
    assert r.status_code == 400
