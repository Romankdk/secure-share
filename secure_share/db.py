"""SQLite storage for file metadata, plus the expiry purge.

Ciphertext blobs live on disk (STORAGE_DIR/<id>); this table only tracks when each one expires,
how many downloads it allows, and a hash of its delete token.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time

import click
from flask import Flask, current_app, g
from flask.cli import with_appcontext

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id                TEXT PRIMARY KEY,
    delete_token_hash TEXT    NOT NULL,  -- SHA-256 of the token; the token itself is never stored
    size              INTEGER NOT NULL,  -- ciphertext bytes
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    max_downloads     INTEGER NOT NULL,
    downloads         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS files_expires_at ON files (expires_at);

-- Recent uploads per visitor, for rate limiting. `client` is HMAC(secret, IP), never the raw IP.
CREATE TABLE IF NOT EXISTS upload_log (
    client TEXT    NOT NULL,
    at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS upload_log_client_at ON upload_log (client, at);
"""

# secrets.token_urlsafe(16) gives exactly 22 URL-safe base64 characters. Anything else is rejected
# before it gets near the filesystem, so an id like "../../etc/passwd" can never become a path.
ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22}$")

# A blob on disk with no database row is normally debris from a crash. A brand-new one may be an
# upload that is about to insert its row, so only remove orphans older than this.
ORPHAN_GRACE_SECONDS = 3600


def valid_id(file_id: str) -> bool:
    return bool(ID_PATTERN.match(file_id))


def blob_path(file_id: str) -> str:
    if not valid_id(file_id):  # defence in depth: callers validate too
        raise ValueError("invalid file id")
    return os.path.join(current_app.config["STORAGE_DIR"], file_id)


def now() -> int:
    return int(current_app.config["CLOCK"]())


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        # isolation_level=None turns off Python's implicit transactions, so the code controls them
        # explicitly. That is what makes "BEGIN IMMEDIATE" in the download route mean what it says.
        # timeout: how long a request waits for another request's write lock before giving up.
        g.db = sqlite3.connect(current_app.config["DATABASE"], isolation_level=None, timeout=15)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def remove_blob(file_id: str) -> None:
    try:
        os.remove(blob_path(file_id))
    except FileNotFoundError:
        pass
    except OSError:
        # e.g. Windows refuses to delete a file another request still has open. The row is already
        # gone, so the blob is now an orphan and the purge sweep will remove it later.
        pass


def purge_expired() -> int:
    """Delete expired files and orphaned blobs. Returns how many expired files were removed."""
    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        ids = [r["id"] for r in conn.execute("SELECT id FROM files WHERE expires_at <= ?", (now(),))]
        conn.executemany("DELETE FROM files WHERE id = ?", [(i,) for i in ids])
        # Rate-limit entries older than the window no longer matter; don't keep visitor data longer than needed.
        conn.execute("DELETE FROM upload_log WHERE at <= ?", (now() - current_app.config["UPLOAD_RATE_WINDOW"],))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    # Files are removed after the commit: if we crash in between, the orphan sweep catches them,
    # whereas deleting first could leave a row pointing at a missing blob.
    for file_id in ids:
        remove_blob(file_id)
    sweep_orphans(conn)
    return len(ids)


def sweep_orphans(conn: sqlite3.Connection) -> None:
    """Remove old blobs that no database row refers to (debris from crashes)."""
    storage = current_app.config["STORAGE_DIR"]
    known = {r["id"] for r in conn.execute("SELECT id FROM files")}
    for name in os.listdir(storage):
        # Only ever touch files this app could have created (<id> or <id>.part), so a misconfigured
        # STORAGE_DIR that also holds the database or anything else can't lose those files.
        file_id = name[:-5] if name.endswith(".part") else name
        if not valid_id(file_id) or name in known:
            continue
        path = os.path.join(storage, name)
        try:
            # Modification times are real wall-clock times, so compare with the real clock here.
            if time.time() - os.path.getmtime(path) > ORPHAN_GRACE_SECONDS:
                os.remove(path)
        except FileNotFoundError:
            pass  # a concurrent upload renamed it, or a download removed it, since listdir()


# How often an upload may trigger a purge. Purging scans the whole table and storage directory,
# so doing it on every request would let anyone make the server do O(n) work per POST.
PURGE_INTERVAL_SECONDS = 60


def purge_if_due() -> None:
    state = current_app.extensions.setdefault("secure_share", {"last_purge": None})
    last = state["last_purge"]
    if last is None or now() - last >= PURGE_INTERVAL_SECONDS:
        state["last_purge"] = now()
        purge_expired()


@click.command("purge")
@with_appcontext
def purge_command() -> None:
    """Delete expired files. Run it from cron, e.g. every 10 minutes."""
    click.echo(f"Purged {purge_expired()} expired file(s).")


def init_app(app: Flask) -> None:
    with app.app_context():
        conn = get_db()
        conn.executescript(SCHEMA)
        # WAL lets the download page's read-only /info requests proceed while an upload writes.
        conn.execute("PRAGMA journal_mode=WAL")
        close_db()
    app.teardown_appcontext(close_db)
    app.cli.add_command(purge_command)
