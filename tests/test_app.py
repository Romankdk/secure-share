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


# What upload.js sends: the custom header plus what a browser adds for a same-origin request.
SAME_SITE = {"X-Requested-With": "secure-share", "Sec-Fetch-Site": "same-origin"}


def upload(client, data=None, expires="1d", max_downloads="1", headers=None):
    data = fake_ciphertext() if data is None else data
    return client.post(
        "/api/files",
        data={"blob": (io.BytesIO(data), "blob.bin"), "expires": expires, "max_downloads": max_downloads},
        content_type="multipart/form-data",
        headers=SAME_SITE if headers is None else headers,
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


def test_expiry_is_checked_under_the_lock(app, client, clock, monkeypatch):
    # The file expires between the quick pre-check and the locked transaction: still 410, still deleted.
    file_id = upload(client, expires="1h").get_json()["id"]
    from secure_share import db
    real = db.immediate_transaction

    def expire_then_lock():
        clock.advance(3600)
        return real()

    monkeypatch.setattr(db, "immediate_transaction", expire_then_lock)
    assert client.get(f"/api/files/{file_id}").status_code == 410
    assert stored_blobs(app) == []


def test_old_database_upgraded_by_two_workers(tmp_path, clock):
    import sqlite3
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE upload_log (client TEXT NOT NULL, at INTEGER NOT NULL)")  # pre-size schema
    conn.commit()
    conn.close()
    config = {"DATABASE": str(path), "STORAGE_DIR": str(tmp_path / "b"), "CLOCK": clock}
    create_app(dict(config))
    create_app(dict(config))  # second worker: column already exists, must not crash
    cols = [r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(upload_log)")]
    assert "size" in cols


def test_expired_download_is_refused_and_deleted(app, client, clock):
    file_id = upload(client, expires="1d").get_json()["id"]
    clock.advance(86400)
    assert client.get(f"/api/files/{file_id}").status_code == 410
    assert stored_blobs(app) == []


def test_head_request_does_not_consume_a_download(client):
    # Link checkers and proxies send HEAD; that must not destroy a one-time file.
    file_id = upload(client, max_downloads="1").get_json()["id"]
    res = client.head(f"/api/files/{file_id}")
    assert res.status_code == 405
    assert res.headers["Allow"] == "GET, DELETE"  # required on 405: every method this URL supports
    assert client.get(f"/api/files/{file_id}/info").get_json()["downloads_left"] == 1


def test_row_without_blob_is_404_and_cleaned_up(app, client):
    file_id = upload(client, max_downloads="3").get_json()["id"]
    os.remove(os.path.join(app.config["STORAGE_DIR"], file_id))
    assert client.get(f"/api/files/{file_id}").status_code == 404
    assert client.get(f"/api/files/{file_id}/info").status_code == 404


def test_failed_write_leaves_no_partial_file(app, client, monkeypatch):
    def disk_full(*_args):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("secure_share.api.os.replace", disk_full)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    res = upload(client)
    assert res.status_code == 500
    assert res.get_json() == {"error": res.get_json()["error"]}  # JSON, no traceback
    assert os.listdir(app.config["STORAGE_DIR"]) == []


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
    res = client.post("/api/files", data={"expires": "1h", "max_downloads": "1"},
                      content_type="multipart/form-data", headers=SAME_SITE)
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


def test_odd_entry_in_storage_does_not_break_cleanup_or_uploads(app, client, clock):
    weird = os.path.join(app.config["STORAGE_DIR"], "d" * 22)
    os.mkdir(weird)  # a directory named like a blob can't be removed with os.remove
    os.utime(weird, (1_000_000_000, 1_000_000_000))
    with app.app_context():
        from secure_share.db import purge_expired
        purge_expired()  # logs a warning instead of raising
    clock.advance(120)
    assert upload(client).status_code == 201


def test_purge_cli(app, client, clock):
    upload(client, expires="1h")
    upload(client, expires="7d")
    clock.advance(7200)
    result = app.test_cli_runner().invoke(args=["purge"])
    assert "Purged 1 expired file(s)." in result.output
    assert len(stored_blobs(app)) == 1


# --- abuse limits --------------------------------------------------------------------------------

def upload_from(client, ip, headers=None):
    return client.post(
        "/api/files",
        data={"blob": (io.BytesIO(fake_ciphertext()), "blob.bin"), "expires": "1h", "max_downloads": "1"},
        content_type="multipart/form-data",
        environ_base={"REMOTE_ADDR": ip},
        headers={**SAME_SITE, **(headers or {})},
    )


def test_upload_rate_limit_per_visitor(app, client, clock):
    app.config["UPLOAD_RATE_LIMIT"] = 3
    assert [upload_from(client, "203.0.113.1").status_code for _ in range(4)] == [201, 201, 201, 429]
    res = upload_from(client, "203.0.113.1")
    assert res.status_code == 429 and res.headers["Retry-After"] == "3600"
    assert "Too many uploads" in res.get_json()["error"]
    assert upload_from(client, "203.0.113.2").status_code == 201  # other visitors unaffected
    clock.advance(3601)
    assert upload_from(client, "203.0.113.1").status_code == 201  # window has passed


def test_raw_ips_are_never_stored(app, client):
    upload_from(client, "203.0.113.77")
    with app.app_context():
        from secure_share.db import get_db
        stored = [r[0] for r in get_db().execute("SELECT client FROM upload_log")]
    assert stored and all("203.0.113.77" not in s for s in stored)


def test_storage_quota(app, client):
    app.config["STORAGE_QUOTA"] = 2500
    assert upload(client, data=fake_ciphertext(1000)).status_code == 201
    assert upload(client, data=fake_ciphertext(1000)).status_code == 201
    res = upload(client, data=fake_ciphertext(1000))
    assert res.status_code == 503
    assert "full" in res.get_json()["error"]


def test_forwarded_ip_ignored_without_a_trusted_proxy(app, client):
    # With no proxy configured, X-Forwarded-For is attacker-controlled and must not reset the limit.
    app.config["UPLOAD_RATE_LIMIT"] = 1
    assert upload_from(client, "203.0.113.5", {"X-Forwarded-For": "198.51.100.1"}).status_code == 201
    assert upload_from(client, "203.0.113.5", {"X-Forwarded-For": "198.51.100.2"}).status_code == 429


def test_forwarded_ip_used_behind_a_trusted_proxy(tmp_path, clock):
    app = create_app({"DATABASE": str(tmp_path / "p.sqlite"), "STORAGE_DIR": str(tmp_path / "pb"),
                      "CLOCK": clock, "TRUSTED_PROXIES": 1, "UPLOAD_RATE_LIMIT": 1})
    client = app.test_client()
    proxy = "10.0.0.1"  # every request arrives from the proxy; the visitor is in the header
    assert upload_from(client, proxy, {"X-Forwarded-For": "198.51.100.1"}).status_code == 201
    assert upload_from(client, proxy, {"X-Forwarded-For": "198.51.100.1"}).status_code == 429
    assert upload_from(client, proxy, {"X-Forwarded-For": "198.51.100.2"}).status_code == 201


def test_per_visitor_daily_byte_limit(app, client, clock):
    # One visitor must not be able to use up the shared storage for everyone.
    app.config["VISITOR_DAILY_BYTES"] = 2500
    assert [upload_from(client, "203.0.113.9").status_code for _ in range(3)] == [201, 201, 429]
    assert "today's upload limit" in upload_from(client, "203.0.113.9").get_json()["error"]
    assert upload_from(client, "203.0.113.10").status_code == 201
    clock.advance(86401)
    assert upload_from(client, "203.0.113.9").status_code == 201


def test_ipv6_visitors_counted_per_64(app, client):
    app.config["UPLOAD_RATE_LIMIT"] = 2
    same_64 = ["2001:db8:1:1::1", "2001:db8:1:1::2", "2001:db8:1:1:ffff::3"]
    assert [upload_from(client, ip).status_code for ip in same_64] == [201, 201, 429]
    assert upload_from(client, "2001:db8:1:2::1").status_code == 201  # a different /64


def test_ipv4_mapped_addresses_are_separate_visitors(app, client):
    # "::ffff:a.b.c.d" is an IPv4 visitor; grouping it by /64 would lump all IPv4 visitors together.
    app.config["UPLOAD_RATE_LIMIT"] = 1
    assert upload_from(client, "::ffff:203.0.113.30").status_code == 201
    assert upload_from(client, "::ffff:203.0.113.31").status_code == 201
    assert upload_from(client, "203.0.113.30").status_code == 429  # same visitor as the mapped form


def test_visitor_address_grouping():
    from secure_share.api import visitor_address
    assert visitor_address("203.0.113.5") == "203.0.113.5"
    assert visitor_address("::ffff:203.0.113.5") == "203.0.113.5"
    assert visitor_address("2001:db8:1:1:aaaa::1") == visitor_address("2001:db8:1:1:bbbb::2") == "2001:db8:1:1::/64"
    assert visitor_address("not-an-ip") == "not-an-ip"


def test_retry_after_matches_the_limit_hit(app, client, clock):
    app.config["VISITOR_DAILY_BYTES"] = 1500
    assert upload_from(client, "203.0.113.40").status_code == 201
    clock.advance(600)
    res = upload_from(client, "203.0.113.40")
    assert res.status_code == 429
    assert res.headers["Retry-After"] == str(86400 - 600)  # until the first upload stops counting


def test_retry_after_waits_for_enough_bytes_to_free_up(app, client, clock):
    app.config["VISITOR_DAILY_BYTES"] = 3500
    for _ in range(3):  # 3 x 1000 bytes, 100 s apart
        assert upload_from(client, "203.0.113.41").status_code == 201
        clock.advance(100)
    # 3000 used; a 2000-byte upload needs 1500 to free up, i.e. the first TWO uploads to expire.
    res = client.post("/api/files", data={"blob": (io.BytesIO(fake_ciphertext(2000)), "b"), "expires": "1h",
                                          "max_downloads": "1"}, content_type="multipart/form-data",
                      environ_base={"REMOTE_ADDR": "203.0.113.41"}, headers=SAME_SITE)
    assert res.status_code == 429
    assert res.headers["Retry-After"] == str(86400 - 200)  # second upload was at +100s; now is +300s


def test_file_bigger_than_daily_allowance_is_413(app, client):
    app.config["VISITOR_DAILY_BYTES"] = 500
    res = upload(client, data=fake_ciphertext(1000))
    assert res.status_code == 413
    assert "daily upload allowance" in res.get_json()["error"]


def test_failed_upload_does_not_count_against_the_visitor(app, client, monkeypatch):
    app.config["UPLOAD_RATE_LIMIT"] = 1
    app.config["PROPAGATE_EXCEPTIONS"] = False

    def disk_full(*_args):
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as m:
        m.setattr("secure_share.api.os.replace", disk_full)
        assert upload_from(client, "203.0.113.50").status_code == 500
    assert upload_from(client, "203.0.113.50").status_code == 201  # the failed attempt was given back


def test_long_rate_window_is_not_cut_short_by_cleanup(app, client, clock):
    app.config["UPLOAD_RATE_LIMIT"] = 1
    app.config["UPLOAD_RATE_WINDOW"] = 7 * 86400
    assert upload_from(client, "203.0.113.60").status_code == 201
    clock.advance(2 * 86400)  # cleanup runs on the next request
    assert upload_from(client, "203.0.113.60").status_code == 429


def test_rate_limit_key_file(tmp_path):
    from secure_share.db import load_or_create_key
    path = str(tmp_path / "k")
    key = load_or_create_key(path)
    assert len(key) == 32 and load_or_create_key(path) == key  # stable across restarts
    assert [p.name for p in tmp_path.iterdir()] == ["k"]  # no temp files left behind
    (tmp_path / "bad").write_bytes(b"short")
    with pytest.raises(RuntimeError, match="delete it"):
        load_or_create_key(str(tmp_path / "bad"))


@pytest.mark.parametrize("headers", [
    {},  # no custom header: a plain cross-site form POST
    {"X-Requested-With": "secure-share", "Sec-Fetch-Site": "cross-site"},
    {"X-Requested-With": "secure-share", "Sec-Fetch-Site": "same-site"},
    {"X-Requested-With": "something-else"},
])
def test_cross_site_uploads_rejected(app, client, headers):
    res = upload(client, headers=headers)
    assert res.status_code == 403
    assert stored_blobs(app) == []


def test_uploads_without_fetch_metadata_still_work(client):
    # Older browsers and command-line clients don't send Sec-Fetch-Site; the custom header suffices.
    assert upload(client, headers={"X-Requested-With": "secure-share"}).status_code == 201


def test_rate_limit_survives_restarts_and_is_shared_by_workers(tmp_path, clock):
    config = {"DATABASE": str(tmp_path / "w.sqlite"), "STORAGE_DIR": str(tmp_path / "wb"),
              "CLOCK": clock, "UPLOAD_RATE_LIMIT": 2}
    worker_a = create_app(dict(config)).test_client()
    worker_b = create_app(dict(config)).test_client()  # another process, or the app after a reload
    codes = [upload_from(c, "203.0.113.20").status_code for c in (worker_a, worker_b, worker_a, worker_b)]
    assert codes == [201, 201, 429, 429]
    key_file = tmp_path / "rate_limit.key"
    assert key_file.stat().st_size == 32
    if os.name == "posix":
        assert key_file.stat().st_mode & 0o777 == 0o600


def test_wal_is_off_by_default(app):
    # PythonAnywhere's storage is a network filesystem, where SQLite's WAL mode isn't safe.
    with app.app_context():
        from secure_share.db import get_db
        assert get_db().execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_deployment_config_behind_proxy(tmp_path, clock):
    """The exact config from the README's PythonAnywhere WSGI file."""
    app = create_app({"DATABASE": str(tmp_path / "d.sqlite"), "STORAGE_DIR": str(tmp_path / "db"),
                      "CLOCK": clock, "TRUSTED_PROXIES": 1, "TRUSTED_HOSTS": ["example.pythonanywhere.com"]})
    client = app.test_client()
    host = "http://example.pythonanywhere.com"
    # The proxy terminates HTTPS and says so in X-Forwarded-Proto: HSTS must be sent.
    res = client.get("/", base_url=host, headers={"X-Forwarded-Proto": "https"})
    assert res.status_code == 200
    assert res.headers["Strict-Transport-Security"] == "max-age=31536000"
    # Requests for any other Host are refused.
    assert client.get("/", base_url="http://evil.example").status_code == 400
    # A forwarded Host header is ignored rather than trusted.
    assert client.get("/", base_url=host, headers={"X-Forwarded-Host": "evil.example"}).status_code == 200


def test_hsts_only_over_https(client):
    assert "Strict-Transport-Security" not in client.get("/").headers
    assert client.get("/", base_url="https://localhost").headers["Strict-Transport-Security"] == "max-age=31536000"


# --- security headers ----------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/f/" + "a" * 22, "/api/files/" + "a" * 22, "/static/crypto.js"])
def test_security_headers_on_every_response(client, path):
    res = client.get(path)
    csp = res.headers["Content-Security-Policy"]
    for directive in ("default-src 'self'", "script-src 'self'", "object-src 'none'",
                      "base-uri 'none'", "frame-ancestors 'none'", "form-action 'self'"):
        assert directive in csp
    assert "unsafe-inline" not in csp
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["Referrer-Policy"] == "no-referrer"
    assert res.headers["Cache-Control"] == "no-store"
    assert res.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert res.headers["Cross-Origin-Opener-Policy"] == "same-origin"


def test_trailing_newline_id_rejected(client):
    assert client.get("/api/files/" + "a" * 22 + "%0A").status_code == 404


def test_pages_have_no_inline_scripts_or_styles(client):
    # The CSP would block them anyway; this catches mistakes before a browser does.
    for path in ("/", "/f/" + "a" * 22):
        html = client.get(path).get_data(as_text=True)
        assert "<script>" not in html and "<style" not in html and "style=" not in html
        assert 'type="module"' in html
