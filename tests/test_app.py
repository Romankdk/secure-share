"""Tests for the secure-share server.

The server only ever handles ciphertext, so these tests upload random bytes as the "encrypted
blob": from the server's point of view, that is exactly what real uploads look like.
"""

import io
import os
import threading

import pytest

from secure_share import create_app
from secure_share.api import hash_token

START = 1_800_000_000  # an arbitrary fixed "now" for the fake clock


class FakeClock:
    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def app(tmp_path, clock):
    return create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.sqlite"),
        "STORAGE_DIR": str(tmp_path / "blobs"),
        "CLOCK": clock,
    })


@pytest.fixture
def client(app):
    return app.test_client()


def fake_ciphertext(size=1000):
    return os.urandom(size)


def upload(client, data=None, expires="1d", max_downloads="1"):
    data = fake_ciphertext() if data is None else data
    return client.post(
        "/api/files",
        data={"blob": (io.BytesIO(data), "blob.bin"), "expires": expires, "max_downloads": max_downloads},
        content_type="multipart/form-data",
    )


def stored_blobs(app):
    return [n for n in os.listdir(app.config["STORAGE_DIR"]) if not n.endswith(".part")]


# --- core flow -----------------------------------------------------------------------------------

def test_upload_download_roundtrip(client):
    data = fake_ciphertext(5000)
    res = upload(client, data)
    assert res.status_code == 201
    body = res.get_json()
    assert set(body) == {"id", "delete_token", "expires_at"}
    assert len(body["id"]) == 22

    got = client.get(f"/api/files/{body['id']}")
    assert got.status_code == 200
    assert got.data == data  # the server hands back exactly the bytes it was given
    assert got.mimetype == "application/octet-stream"


def test_one_time_link_self_destructs(app, client):
    file_id = upload(client, max_downloads="1").get_json()["id"]
    assert client.get(f"/api/files/{file_id}").status_code == 200
    assert client.get(f"/api/files/{file_id}").status_code == 404
    assert client.get(f"/api/files/{file_id}/info").status_code == 404
    assert stored_blobs(app) == []  # the ciphertext is gone from disk too


def test_multi_download_limit(app, client):
    file_id = upload(client, max_downloads="3").get_json()["id"]
    lefts = [client.get(f"/api/files/{file_id}").headers["X-Downloads-Left"] for _ in range(3)]
    assert lefts == ["2", "1", "0"]
    assert client.get(f"/api/files/{file_id}").status_code == 404
    assert stored_blobs(app) == []


def test_expiry_with_fake_clock(app, client, clock):
    file_id = upload(client, expires="1h", max_downloads="5").get_json()["id"]
    clock.advance(3599)
    assert client.get(f"/api/files/{file_id}/info").status_code == 200
    clock.advance(1)  # exactly one hour: expired
    assert client.get(f"/api/files/{file_id}/info").status_code == 410
    assert client.get(f"/api/files/{file_id}").status_code == 404  # and it was deleted
    assert stored_blobs(app) == []


def test_expired_download_is_refused_and_deleted(app, client, clock):
    file_id = upload(client, expires="1d").get_json()["id"]
    clock.advance(86400)
    assert client.get(f"/api/files/{file_id}").status_code == 410
    assert stored_blobs(app) == []


def test_info_does_not_consume_a_download(client):
    file_id = upload(client, max_downloads="1").get_json()["id"]
    for _ in range(5):
        info = client.get(f"/api/files/{file_id}/info")
        assert info.status_code == 200
        assert info.get_json()["downloads_left"] == 1
    assert client.get(f"/api/files/{file_id}").status_code == 200


def test_download_page_does_not_consume_a_download(client):
    # Chat-app link previews fetch the page URL; that must not burn a one-time link.
    file_id = upload(client, max_downloads="1").get_json()["id"]
    for _ in range(3):
        assert client.get(f"/f/{file_id}").status_code == 200
    assert client.get(f"/api/files/{file_id}/info").get_json()["downloads_left"] == 1


def test_concurrent_downloads_of_one_time_link(app):
    """Many simultaneous requests for a one-time file: exactly one may succeed."""
    file_id = upload(app.test_client(), max_downloads="1").get_json()["id"]
    statuses = []
    barrier = threading.Barrier(8)

    def grab():
        client = app.test_client()
        barrier.wait()
        statuses.append(client.get(f"/api/files/{file_id}").status_code)

    threads = [threading.Thread(target=grab) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(statuses) == [200] + [404] * 7


# --- input validation ----------------------------------------------------------------------------

@pytest.mark.parametrize("bad_id", [
    "short",
    "A" * 23,
    "has.dot.in.it.abcdefgh",
    "..%2F..%2Fetc%2Fpasswd",
    "%2E%2E%2F%2E%2E%2Fsecret_",
])
def test_invalid_ids_return_404(client, bad_id):
    for url in (f"/api/files/{bad_id}", f"/api/files/{bad_id}/info", f"/f/{bad_id}"):
        assert client.get(url).status_code == 404, url
    assert client.delete(f"/api/files/{bad_id}", headers={"X-Delete-Token": "x"}).status_code == 404


def test_path_traversal_cannot_read_files_outside_storage(app, client, tmp_path):
    secret = tmp_path / "secret_file_abcdefghijk"
    secret.write_bytes(b"top secret")
    for url in ("/api/files/../secret_file_abcdefghijk", "/api/files/..%2Fsecret_file_abcdefghij"):
        res = client.get(url)
        assert res.status_code == 404
        assert b"top secret" not in res.data


def test_unknown_but_well_formed_id_is_404(client):
    assert client.get("/api/files/" + "a" * 22).status_code == 404
    assert client.get("/api/files/" + "a" * 22 + "/info").status_code == 404


@pytest.mark.parametrize("expires", ["", "2h", "1H", "forever", "3600"])
def test_bad_expiry_is_400(client, expires):
    assert upload(client, expires=expires).status_code == 400


@pytest.mark.parametrize("max_downloads", ["", "0", "11", "-1", "1.5", "abc", " 3", "1e1", "²", "٣", "007"])
def test_bad_max_downloads_is_400(client, max_downloads):
    assert upload(client, max_downloads=max_downloads).status_code == 400


def test_missing_or_tiny_blob_is_400(client):
    res = client.post("/api/files", data={"expires": "1h", "max_downloads": "1"}, content_type="multipart/form-data")
    assert res.status_code == 400
    assert upload(client, data=b"too short").status_code == 400


def test_oversized_upload_is_413_json(app, client):
    too_big = app.config["MAX_CONTENT_LENGTH"] + 1
    res = upload(client, data=b"\0" * too_big)
    assert res.status_code == 413
    assert "too large" in res.get_json()["error"]
    assert stored_blobs(app) == []


def test_file_of_exactly_max_size_is_accepted(app, client):
    # A 25 MB file grows by the IV, tag and encrypted header; that must still fit.
    res = upload(client, data=b"\0" * (app.config["MAX_FILE_SIZE"] + 12 + 16 + 200))
    assert res.status_code == 201


# --- delete --------------------------------------------------------------------------------------

def test_delete_with_right_token(app, client):
    body = upload(client).get_json()
    res = client.delete(f"/api/files/{body['id']}", headers={"X-Delete-Token": body["delete_token"]})
    assert res.status_code == 204
    assert client.get(f"/api/files/{body['id']}").status_code == 404
    assert stored_blobs(app) == []


def test_delete_with_wrong_or_missing_token(client):
    body = upload(client).get_json()
    assert client.delete(f"/api/files/{body['id']}", headers={"X-Delete-Token": "wrong"}).status_code == 403
    assert client.delete(f"/api/files/{body['id']}").status_code == 401
    assert client.get(f"/api/files/{body['id']}").status_code == 200  # still there


def test_only_a_hash_of_the_delete_token_is_stored(app, client):
    body = upload(client).get_json()
    with app.app_context():
        from secure_share.db import get_db
        stored = get_db().execute("SELECT delete_token_hash FROM files").fetchone()[0]
    assert stored == hash_token(body["delete_token"])
    assert body["delete_token"] not in stored


# --- purge ---------------------------------------------------------------------------------------

def test_upload_purges_expired_files(app, client, clock):
    old = upload(client, expires="1h").get_json()["id"]
    clock.advance(7200)
    upload(client)  # any upload triggers cleanup
    assert old not in stored_blobs(app)


def test_upload_purge_is_throttled(app, client, clock, monkeypatch):
    from secure_share import db
    calls = []
    monkeypatch.setattr(db, "purge_expired", lambda: calls.append(clock.now))
    upload(client)
    upload(client)  # same instant: no second purge
    clock.advance(61)
    upload(client)
    assert calls == [START, START + 61]


def test_invalid_upload_does_no_cleanup_work(app, client, monkeypatch):
    from secure_share import db
    monkeypatch.setattr(db, "purge_expired", lambda: pytest.fail("purged on an invalid request"))
    assert upload(client, expires="bogus").status_code == 400


def test_orphan_sweep_only_touches_old_blob_files(app, client):
    storage = app.config["STORAGE_DIR"]
    old = 1_000_000_000  # file mtime far in the past (the sweep uses real file times)
    paths = {
        "orphan": os.path.join(storage, "o" * 22),
        "orphan_part": os.path.join(storage, "p" * 22 + ".part"),
        "fresh_orphan": os.path.join(storage, "f" * 22),
        "not_ours": os.path.join(storage, "secure_share.sqlite"),
    }
    for name, path in paths.items():
        with open(path, "wb") as f:
            f.write(b"x")
        if name != "fresh_orphan":
            os.utime(path, (old, old))
    kept_id = upload(client).get_json()["id"]
    os.utime(os.path.join(storage, kept_id), (old, old))

    with app.app_context():
        from secure_share.db import purge_expired
        purge_expired()
    remaining = set(os.listdir(storage))
    assert remaining == {"f" * 22, "secure_share.sqlite", kept_id}


def test_purge_cli(app, client, clock):
    upload(client, expires="1h")
    upload(client, expires="7d")
    clock.advance(7200)
    result = app.test_cli_runner().invoke(args=["purge"])
    assert "Purged 1 expired file(s)." in result.output
    assert len(stored_blobs(app)) == 1


# --- security headers ----------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/f/" + "a" * 22, "/api/files/" + "a" * 22, "/static/crypto.js"])
def test_security_headers_on_every_response(client, path):
    res = client.get(path)
    csp = res.headers["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "object-src 'none'",
                      "base-uri 'none'", "frame-ancestors 'none'"):
        assert directive in csp
    assert "unsafe-inline" not in csp
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["Referrer-Policy"] == "no-referrer"
    assert res.headers["Cache-Control"] == "no-store"


def test_pages_have_no_inline_scripts_or_styles(client):
    # The CSP would block them anyway; this catches mistakes before a browser does.
    for path in ("/", "/f/" + "a" * 22):
        html = client.get(path).get_data(as_text=True)
        assert "<script>" not in html and "<style" not in html and "style=" not in html
        assert 'type="module"' in html
