"""Smoke test: every page renders for a user and an admin, with and without data."""
import re

from helpers import login, make_admin, make_pdf, register, upload


def test_all_pages_render(app):
    make_admin(app)
    u, a = app.test_client(), app.test_client()
    register(u); login(u); login(a, "admin")
    upload(u, "one.pdf", make_pdf("1"))
    pid = re.search(rb"/files/([0-9a-f]{32})/download", u.get("/files").data).group(1).decode()
    upload(u, "one.pdf", make_pdf("2"), target=pid)
    u.post(f"/files/{pid}/verify")
    pages = ["/dashboard", "/files", "/files?q=one", "/upload", f"/upload?file={pid}", f"/files/{pid}/versions",
             "/incidents", "/incidents?date_from=2020-01-01&date_to=2099-01-01", "/risk"]
    for url in pages:
        r = u.get(url)
        assert r.status_code == 200, url
        assert b"VaultGuard" in r.data
    for url in ["/admin", "/incidents", "/dashboard", "/risk"]:
        assert a.get(url).status_code == 200, url
    assert u.get("/nope").status_code == 404
    assert b"Not found" in u.get("/nope").data


def test_empty_state_pages(client):
    register(client); login(client)
    for url in ["/dashboard", "/files", "/upload", "/incidents", "/risk"]:
        assert client.get(url).status_code == 200, url
    assert client.get("/incidents?date_from=garbage").status_code == 200
