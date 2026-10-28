"""SQLite storage for file metadata, plus the expiry purge.

Ciphertext blobs live on disk (STORAGE_DIR/<id>); this table only tracks when each one expires,
how many downloads it allows, and a hash of its delete token.
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

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
    at     INTEGER NOT NULL,
    size   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS upload_log_client_at ON upload_log (client, at);
"""

# secrets.token_urlsafe(16) gives exactly 22 URL-safe base64 characters. Anything else is rejected
# before it gets near the filesystem, so an id like "../../etc/passwd" can never become a path.
# (fullmatch, not match + "$": "$" would also accept a trailing newline.)
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{22}")

# A blob on disk with no database row is normally debris from a crash. A brand-new one may be an
# upload that is about to insert its row, so only remove orphans older than this.
ORPHAN_GRACE_SECONDS = 3600

def valid_id(file_id: str) -> bool:
    return bool(ID_PATTERN.fullmatch(file_id))


def blob_path(file_id: str) -> str:
    if not valid_id(file_id):  # defence in depth: callers validate too
        raise ValueError("invalid file id")
    return os.path.join(current_app.config["STORAGE_DIR"], file_id)


def now() -> int:
    return int(current_app.config["CLOCK"]())


KEY_BYTES = 32

# How long a request waits for another request's database write lock before failing.
LOCK_WAIT_SECONDS = 15


def load_or_create_key(path: str) -> bytes:
    """A secret that stays the same across restarts and worker processes.

    The key is written in full to a private temporary file first and then linked into place.
    os.link fails if the target exists, so when two processes start at once exactly one key wins,
    and a crash mid-write can never leave a truncated key file at `path` (which would stop every
    later start). Mode 0600: only this account can read it.
    """
    if not os.path.exists(path):
        tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        # O_BINARY: on Windows, text mode would turn any 0x0A byte of the key into 0x0D 0x0A.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(KEY_BYTES))
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass  # another process won the race; use its key
            except OSError:
                # Filesystem without hard links. Never rename over `path` (a worker that already
                # loaded the old key would then disagree with the others); create it exclusively.
                _create_key_exclusively(path)
        finally:
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != KEY_BYTES:
        raise RuntimeError(f"{path} doesn't hold a {KEY_BYTES}-byte key; delete it to generate a new one")
    return key


def _create_key_exclusively(path: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, "wb") as f:
        f.write(secrets.token_bytes(KEY_BYTES))
        f.flush()
        os.fsync(f.fileno())


@contextmanager
def immediate_transaction() -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT, rolling back if anything (including abort()) is raised.

    IMMEDIATE takes SQLite's write lock at BEGIN rather than at the first write, so a
    read-check-then-write sequence inside the block can't be interleaved with another request's.
    """
    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        # isolation_level=None turns off Python's implicit transactions, so the code controls them
        # explicitly. That is what makes "BEGIN IMMEDIATE" in the download route mean what it says.
        # timeout: how long a request waits for another request's write lock before giving up.
        g.db = sqlite3.connect(current_app.config["DATABASE"], isolation_level=None, timeout=LOCK_WAIT_SECONDS)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def remove_blob(file_id: str) -> None:
    try:
        os.remove(blob_path(file_id))
    except FileNotFoundError:
        pass
    except OSError as e:
        # e.g. Windows refuses to delete a file another request still has open. The row is already
        # gone, so the blob is now an orphan and the purge sweep will retry. Log it: ciphertext
        # that was supposed to be deleted shouldn't linger silently.
        current_app.logger.warning("could not remove blob %s: %s", file_id, e)


def purge_expired() -> int:
    """Delete expired files and orphaned blobs. Returns how many expired files were removed."""
    cfg = current_app.config
    # Don't keep (hashed) visitor data longer than the longest limit window needs it.
    retention = max(cfg["UPLOAD_RATE_WINDOW"], cfg["VISITOR_BYTES_WINDOW"])
    with immediate_transaction() as conn:
        ids = [r["id"] for r in conn.execute("SELECT id FROM files WHERE expires_at <= ?", (now(),))]
        conn.executemany("DELETE FROM files WHERE id = ?", [(i,) for i in ids])
        conn.execute("DELETE FROM upload_log WHERE at <= ?", (now() - retention,))
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
        except OSError as e:
            # One odd entry (a directory, a permissions problem) must not break every purge.
            current_app.logger.warning("could not remove orphan %s: %s", name, e)


PURGE_LOCK_WAIT_MS = 500

# How often requests may trigger a purge. Purging scans the whole table and storage directory,
# so doing it on every request would let anyone make the server do O(n) work per request.
PURGE_INTERVAL_SECONDS = 60


def purge_if_due() -> None:
    """Opportunistic, throttled cleanup driven by site traffic. Never fails the calling request."""
    state = current_app.extensions.setdefault("secure_share", {"last_purge": None})
    last = state["last_purge"]
    if last is None or now() - last >= PURGE_INTERVAL_SECONDS:
        state["last_purge"] = now()
        conn = get_db()
        # Cleanup piggybacks on visitors' requests, so don't make them wait long if another request
        # holds the write lock: give up quickly and let a later request retry.
        conn.execute(f"PRAGMA busy_timeout = {PURGE_LOCK_WAIT_MS}")
        try:
            purge_expired()
        except Exception:  # noqa: BLE001 - cleanup is best effort; the next request retries
            current_app.logger.exception("purge failed")
        finally:
            conn.execute(f"PRAGMA busy_timeout = {LOCK_WAIT_SECONDS * 1000}")


@click.command("purge")
@with_appcontext
def purge_command() -> None:
    """Delete expired files now. Site traffic already triggers this; only schedule it (e.g. cron)
    when it runs on the same machine as the web app, never against SQLite over network storage."""
    click.echo(f"Purged {purge_expired()} expired file(s).")


def init_app(app: Flask) -> None:
    with app.app_context():
        conn = get_db()
        conn.executescript(SCHEMA)
        # Databases created before upload_log had a size column.
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(upload_log)")}
        if "size" not in columns:
            try:
                conn.execute("ALTER TABLE upload_log ADD COLUMN size INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError as e:
                if "duplicate column" not in str(e):  # another worker just added it: fine
                    raise
        mode = "wal" if app.config["SQLITE_WAL"] else "delete"
        if conn.execute("PRAGMA journal_mode").fetchone()[0] != mode:
            # Switching needs exclusive access. If another process has the database open, don't
            # hold up startup for the full lock wait: keep the current mode and say so.
            conn.execute("PRAGMA busy_timeout = 1000")
            try:
                conn.execute(f"PRAGMA journal_mode={mode}")
            except sqlite3.OperationalError as e:
                app.logger.warning("could not set journal_mode=%s (%s); will retry on next start", mode, e)
        close_db()
    app.teardown_appcontext(close_db)
    app.cli.add_command(purge_command)
