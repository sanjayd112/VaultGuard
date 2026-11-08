import pytest

from encryption import (ConfigurationError, DecryptionError, decrypt, encrypt, generate_key, load_key)
from helpers import PASSWORD, login, make_pdf, register, upload
from models import File, FileVersion


@pytest.fixture
def user(client):
    register(client); login(client)
    return client


def test_aes_gcm_roundtrip_and_tamper_detection():
    key = load_key(generate_key())
    blob, nonce = encrypt(b"secret data", key, b"ctx")
    assert len(nonce) == 12 and b"secret data" not in blob
    assert decrypt(blob, key, b"ctx") == b"secret data"
    with pytest.raises(DecryptionError):
        decrypt(blob, key, b"other-context")
    bad = bytearray(blob); bad[-1] ^= 1
    with pytest.raises(DecryptionError):
        decrypt(bytes(bad), key, b"ctx")


def test_missing_or_invalid_key_fails_securely():
    with pytest.raises(ConfigurationError):
        load_key(None)
    with pytest.raises(ConfigurationError):
        load_key("too-short")


def test_app_stops_with_configuration_error_when_key_missing(tmp_path):
    from app import create_app
    app = create_app({"TESTING": True, "SECRET_KEY": "x", "ENCRYPTION_KEY": None, "WTF_CSRF_ENABLED": False,
                      "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'k.db'}", "STORAGE_DIR": tmp_path / "e"})
    r = app.test_client().get("/login")
    assert r.status_code == 503 and b"ENCRYPTION_KEY" in r.data


def test_upload_pdf_is_encrypted_and_original_not_stored(app, user):   # TESTS 3, 4, 5
    pdf = make_pdf("TOP-SECRET-MARKER-12345")
    r = upload(user, "report.pdf", pdf)
    j = r.get_json()
    assert r.status_code == 200 and j["ok"] and j["integrity"] == "verified"
    stored = list(app.config["STORAGE_DIR"].iterdir())
    assert len(stored) == 1 and stored[0].suffix == ".vgenc"          # exactly one file, no plaintext copy, no temp
    raw = stored[0].read_bytes()
    assert raw.startswith(b"VGE1") and b"%PDF" not in raw and b"TOP-SECRET-MARKER" not in raw
    assert len(raw) == len(pdf) + 4 + 12 + 16                         # magic + nonce + ciphertext + GCM tag
    with app.app_context():
        v = FileVersion.query.one()
        assert v.stored_name == stored[0].name and v.nonce_hex == j["nonce"]
        assert "report" not in v.stored_name                          # identifier is random, not user input


def test_download_decrypts_to_identical_bytes(user):                   # TESTS 6, 7
    pdf = make_pdf("Download me")
    upload(user, "thesis.pdf", pdf)
    r = user.get("/files")
    assert b"thesis.pdf" in r.data
    pid = __import__("re").search(rb"/files/([0-9a-f]{32})/download", r.data).group(1).decode()
    d = user.get(f"/files/{pid}/download")
    assert d.status_code == 200 and d.data == pdf
    assert d.headers["Content-Type"] == "application/pdf" and "attachment" in d.headers["Content-Disposition"]


def test_every_upload_uses_a_unique_nonce(app, user):
    nonces = {upload(user, "same.pdf", make_pdf("same")).get_json()["nonce"] for _ in range(5)}
    assert len(nonces) == 5


@pytest.mark.parametrize("name,data,mime", [
    ("malware.exe", b"MZ\x90\x00", "application/octet-stream"),
    ("fake.pdf", b"this is not a pdf", "application/pdf"),
    ("report.pdf", make_pdf(), "image/png"),
    ("empty.txt", b"", "text/plain"),
])
def test_invalid_uploads_are_rejected(app, user, name, data, mime):
    r = upload(user, name, data, mime)
    assert r.status_code == 400 and not r.get_json()["ok"]
    assert list(app.config["STORAGE_DIR"].iterdir()) == []


def test_oversize_upload_rejected(app, user):
    big = b"%PDF-1.4\n" + b"A" * (1024 * 1024 + 10)
    r = upload(user, "big.pdf", big)
    assert r.status_code in (400, 413) and list(app.config["STORAGE_DIR"].iterdir()) == []


def test_path_traversal_filename_is_neutralised(app, user):
    r = upload(user, "../../etc/evil.pdf", make_pdf())
    assert r.get_json()["ok"]
    assert [p.name for p in app.config["STORAGE_DIR"].iterdir() if p.is_file()] and not (app.config["STORAGE_DIR"].parent.parent / "evil.pdf").exists()
    with app.app_context():
        assert "/" not in File.query.one().original_name and ".." not in File.query.one().original_name
