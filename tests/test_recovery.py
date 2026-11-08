import pytest

from helpers import login, make_pdf, register, upload
from models import File, Incident, SecurityEvent


@pytest.fixture
def two_versions(app, client):
    register(client); login(client)
    v1, v2 = make_pdf("VERSION ONE"), make_pdf("VERSION TWO changed")
    upload(client, "plan.pdf", v1)
    with app.app_context():
        pid = File.query.one().public_id
    r = upload(client, "plan.pdf", v2, target=pid)                       # TEST 9
    assert r.get_json()["version"] == 2
    return client, pid, v1, v2


def test_new_version_preserves_previous_encrypted_version(app, two_versions):
    client, pid, v1, v2 = two_versions
    with app.app_context():
        f = File.query.one()
        assert [v.version_number for v in f.versions] == [1, 2] and f.current_version == 2
        assert len(list(app.config["STORAGE_DIR"].iterdir())) == 2
        assert f.version(1).plaintext_sha256 != f.version(2).plaintext_sha256
    assert client.get(f"/files/{pid}/download?version=1").data == v1
    assert client.get(f"/files/{pid}/download").data == v2
    assert b"Version history" in client.get(f"/files/{pid}/versions").data


def test_restore_previous_verified_version_creates_new_version(app, two_versions):   # TEST 10
    client, pid, v1, v2 = two_versions
    r = client.post(f"/files/{pid}/restore/1", follow_redirects=True)
    assert b"restored as version 3" in r.data
    with app.app_context():
        f = File.query.one()
        assert f.current_version == 3 and len(f.versions) == 3          # history never deleted
        assert f.version(3).restored_from == 1
        assert Incident.query.filter_by(event_type="version_restored").count() == 1
    assert client.get(f"/files/{pid}/download").data == v1


def test_corrupted_version_is_never_restored(app, two_versions):
    client, pid, v1, v2 = two_versions
    with app.app_context():
        path = app.config["STORAGE_DIR"] / File.query.one().version(1).stored_name
    raw = bytearray(path.read_bytes()); raw[30] ^= 0xAA; path.write_bytes(bytes(raw))
    r = client.post(f"/files/{pid}/restore/1", follow_redirects=True)
    assert b"Recovery rejected" in r.data
    with app.app_context():
        f = File.query.one()
        assert f.current_version == 2 and len(f.versions) == 2
        assert Incident.query.filter_by(event_type="recovery_rejected").count() == 1


def test_invalid_recovery_request_is_scored(app, two_versions):
    client, pid, *_ = two_versions
    client.post(f"/files/{pid}/restore/99", follow_redirects=True)
    with app.app_context():
        ev = SecurityEvent.query.filter_by(event_type="invalid_recovery_request").one()
        assert ev.points == 20


def test_cannot_restore_someone_elses_version(app, two_versions):
    _, pid, *_ = two_versions
    other = app.test_client(); register(other, "mallory"); login(other, "mallory")
    assert other.post(f"/files/{pid}/restore/1").status_code == 403
    with app.app_context():
        assert File.query.one().current_version == 2


def test_new_version_must_match_file_type(client):
    import re
    register(client); login(client)
    upload(client, "a.pdf")
    pid = re.search(rb"/files/([0-9a-f]{32})/download", client.get("/files").data).group(1).decode()
    assert upload(client, "a.txt", b"hello", "text/plain", target=pid).status_code == 400
