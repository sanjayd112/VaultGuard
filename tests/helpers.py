import io
import re

PASSWORD = "Str0ngPassw0rd!"


def make_pdf(text="VaultGuard test document"):
    """Build a small but structurally valid PDF (computes the xref offsets)."""
    content = f"BT /F1 18 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def register(client, username="alice", password=PASSWORD, email=None):
    r = client.post("/register", data={"username": username, "email": email or f"{username}@example.com",
                                       "password": password, "confirm": password})
    m = re.search(rb'id="recoveryCode">([0-9A-F-]+)<', r.data)
    return r, (m.group(1).decode() if m else None)


def login(client, username="alice", password=PASSWORD):
    return client.post("/login", data={"username": username, "password": password})


def upload(client, name="report.pdf", data=None, mimetype="application/pdf", target=None):
    data = data if data is not None else make_pdf()
    form = {"file": (io.BytesIO(data), name, mimetype)}
    if target:
        form["target_file_id"] = target
    return client.post("/upload", data=form, content_type="multipart/form-data")


def make_admin(app, username="admin", password=PASSWORD):
    from models import User, db
    from security import hash_secret
    with app.app_context():
        db.session.add(User(username=username, email=f"{username}@example.com", role="admin",
                            password_hash=hash_secret(password), recovery_code_hash=hash_secret("ABCDEF0123456789")))
        db.session.commit()
