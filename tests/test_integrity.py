import re

import pytest

from helpers import login, make_pdf, register, upload
from models import File, FileVersion, Incident, SecurityEvent


@pytest.fixture
def stored(app, client):
    register(client); login(client)
    upload(client, "doc.pdf", make_pdf("integrity"))
    with app.app_context():
        f = File.query.one()
        v = f.current
        return client, f.public_id, app.config["STORAGE_DIR"] / v.stored_name


def test_untouched_file_verifies(app, stored):
    client, pid, path = stored
    r = client.post(f"/files/{pid}/verify", follow_redirects=True)
    assert b"Integrity verified" in r.data
    with app.app_context():
        assert Incident.query.filter_by(event_type="integrity_verification", status="ok").count() == 1


def test_modified_encrypted_file_fails_verification(app, stored):      # TEST 8
    client, pid, path = stored
    raw = bytearray(path.read_bytes()); raw[40] ^= 0xFF; path.write_bytes(bytes(raw))
    r = client.post(f"/files/{pid}/verify", follow_redirects=True)
    assert b"INTEGRITY FAILURE" in r.data
    with app.app_context():
        assert File.query.one().current.integrity_status == "failed"
        inc = Incident.query.filter_by(event_type="tampering_detected").one()
        assert inc.status == "critical"
        assert SecurityEvent.query.filter_by(event_type="integrity_failure").count() == 1


def test_download_of_tampered_file_returns_no_content(app, stored):
    client, pid, path = stored
    raw = bytearray(path.read_bytes()); raw[-3] ^= 0x01; path.write_bytes(bytes(raw))
    r = client.get(f"/files/{pid}/download")
    assert r.status_code == 302 and b"%PDF" not in r.data
    assert b"Download blocked" in client.get(f"/files/{pid}/versions").data


def test_tag_only_modification_is_caught_by_gcm_even_if_digest_is_updated(app, stored):
    """Attacker edits ciphertext AND the stored ciphertext hash: AES-GCM authentication still fails."""
    client, pid, path = stored
    from encryption import sha256_hex
    from models import db
    raw = bytearray(path.read_bytes()); raw[20] ^= 0x10; path.write_bytes(bytes(raw))
    with app.app_context():
        v = FileVersion.query.one(); v.ciphertext_sha256 = sha256_hex(bytes(raw)); db.session.commit()
    r = client.post(f"/files/{pid}/verify", follow_redirects=True)
    assert b"AES-GCM authentication failed" in r.data


def test_truncated_and_missing_files_detected(app, stored):
    client, pid, path = stored
    path.write_bytes(path.read_bytes()[:10])
    assert b"INTEGRITY FAILURE" in client.post(f"/files/{pid}/verify", follow_redirects=True).data
    path.unlink()
    assert b"missing" in client.post(f"/files/{pid}/verify", follow_redirects=True).data
