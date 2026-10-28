"""JSON API. Everything here handles ciphertext only; no endpoint can see or produce plaintext."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3

from flask import Blueprint, Response, abort, current_app, jsonify, request
from werkzeug.exceptions import MethodNotAllowed, TooManyRequests

from . import db

bp = Blueprint("api", __name__, url_prefix="/api/files")

EXPIRY_CHOICES = {"1h": 3600, "1d": 86400, "7d": 7 * 86400}
MAX_DOWNLOADS_RANGE = range(1, 11)
MAX_DOWNLOADS_PATTERN = re.compile(r"[0-9]{1,2}")

# Smallest possible valid upload: 12-byte IV + 16-byte GCM tag + a 4-byte header length.
MIN_BLOB_SIZE = 12 + 16 + 4

# Value of the X-Requested-With header the upload page sends (see require_same_site_request).
UPLOAD_CLIENT_HEADER = "secure-share"

NOT_FOUND = "File not found. It may have been downloaded, deleted or expired."


def hash_token(token: str) -> str:
    # Plain SHA-256 is enough here (no slow password hash needed): the token is 256 random bits,
    # so there is nothing to brute-force. Storing only the hash means a leaked database can't be
    # used to delete files.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_valid_id(file_id: str) -> None:
    # Same answer for "malformed" and "doesn't exist", so probing reveals nothing.
    if not db.valid_id(file_id):
        abort(404, NOT_FOUND)


def downloads_left(row: sqlite3.Row) -> int:
    return row["max_downloads"] - row["downloads"]


# --- abuse limits ----------------------------------------------------------------------------------

def visitor_address(ip: str) -> str:
    """The unit a rate limit applies to: the IPv4 address, or the IPv6 /64."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            # "::ffff:1.2.3.4" is an IPv4 visitor seen through an IPv6 socket. Treat it as the IPv4
            # address; grouping it by /64 would put every IPv4 visitor in one shared bucket.
            return str(addr.ipv4_mapped)
        # One IPv6 customer usually controls a whole /64 (2^64 addresses) and could use a fresh
        # address per upload, so the whole /64 counts as one visitor.
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def client_key() -> str:
    """An opaque per-visitor key: HMAC of the address, so raw IPs are never stored.
    Behind a proxy, request.remote_addr is the real visitor only if TRUSTED_PROXIES is set."""
    address = visitor_address(request.remote_addr or "unknown")
    return hmac.new(current_app.config["RATE_LIMIT_KEY"], address.encode(), hashlib.sha256).hexdigest()


def require_same_site_request() -> None:
    """Refuse uploads triggered by other websites.

    Without this, any web page could make each of its visitors' browsers POST junk here: a form
    or a "no-cors" fetch is a "simple" request that browsers send cross-site without asking. Every
    visitor has a different IP, so that would sidestep the per-visitor limits entirely.
    Two independent checks:
      * Sec-Fetch-Site, which modern browsers set and pages can't forge, must say same-origin.
      * A custom header must be present. Browsers only send custom headers cross-site after a CORS
        preflight, which this app never approves, so older browsers are covered too.
    Non-browser clients (curl, scripts) can set the header; they're still limited per IP.
    """
    site = request.headers.get("Sec-Fetch-Site")
    if site is not None and site not in ("same-origin", "none"):
        abort(403, "Uploads must come from this site.")
    if request.headers.get("X-Requested-With") != UPLOAD_CLIENT_HEADER:
        abort(403, "Uploads must come from this site.")


def retry_after(conn: sqlite3.Connection, client: str, since: int, window: int, now: int) -> int:
    """Seconds until this visitor's oldest upload in the window stops counting."""
    oldest = conn.execute(
        "SELECT MIN(at) FROM upload_log WHERE client = ? AND at > ?", (client, since)
    ).fetchone()[0]
    return max(1, (oldest or now) + window - now)


def retry_after_bytes(conn: sqlite3.Connection, client: str, since: int, window: int, now: int,
                      needed: int) -> int:
    """Seconds until enough of this visitor's earlier uploads leave the window to fit `needed` bytes."""
    rows = conn.execute(
        "SELECT at, size FROM upload_log WHERE client = ? AND at > ? ORDER BY at", (client, since)
    ).fetchall()
    freed = 0
    for at, size in rows:
        freed += size
        if freed >= needed:
            return max(1, at + window - now)
    return window  # can't happen when called correctly; the whole window is a safe upper bound


def reserve_upload(size: int) -> int:
    """Check this visitor's limits and the storage quota, and record the upload.

    Returns the upload_log row id, so a failed upload can give the reservation back.
    """
    cfg = current_app.config
    client = client_key()
    now = db.now()
    hour_start = now - cfg["UPLOAD_RATE_WINDOW"]
    day_start = now - cfg["VISITOR_BYTES_WINDOW"]
    with db.immediate_transaction() as conn:
        recent = conn.execute(
            "SELECT COUNT(*) FROM upload_log WHERE client = ? AND at > ?", (client, hour_start)
        ).fetchone()[0]
        if recent >= cfg["UPLOAD_RATE_LIMIT"]:
            wait = retry_after(conn, client, hour_start, cfg["UPLOAD_RATE_WINDOW"], now)
            raise TooManyRequests("Too many uploads from your network. Please try again later.", retry_after=wait)

        # A per-visitor byte budget, so one visitor can't use up the shared storage quota (which
        # would lock everyone else out until their files expired, up to 7 days).
        uploaded = conn.execute(
            "SELECT COALESCE(SUM(size), 0) FROM upload_log WHERE client = ? AND at > ?", (client, day_start)
        ).fetchone()[0]
        if uploaded + size > cfg["VISITOR_DAILY_BYTES"]:
            if size > cfg["VISITOR_DAILY_BYTES"]:
                abort(413, "This file is larger than the daily upload allowance.")
            excess = uploaded + size - cfg["VISITOR_DAILY_BYTES"]
            wait = retry_after_bytes(conn, client, day_start, cfg["VISITOR_BYTES_WINDOW"], now, excess)
            raise TooManyRequests("You've reached today's upload limit. Please try again later.", retry_after=wait)

        # Concurrent uploads can each pass this check, so the quota can be overshot by a few files;
        # it's a guard against filling the disk, not an exact accounting system.
        used = conn.execute("SELECT COALESCE(SUM(size), 0) FROM files").fetchone()[0]
        if used + size > cfg["STORAGE_QUOTA"]:
            abort(503, "The server is full right now. Please try again later.")

        return conn.execute(
            "INSERT INTO upload_log (client, at, size) VALUES (?, ?, ?)", (client, now, size)
        ).lastrowid


def release_upload(reservation: int) -> None:
    """Give back a reservation for an upload that failed, so it doesn't count against the visitor."""
    with db.immediate_transaction() as conn:
        conn.execute("DELETE FROM upload_log WHERE rowid = ?", (reservation,))


# --- routes ----------------------------------------------------------------------------------------

@bp.post("")
def upload():
    require_same_site_request()
    # Validate everything before doing any work, so junk requests stay cheap.
    # (The request body's size was already capped by MAX_CONTENT_LENGTH before this code ran.)
    expires = request.form.get("expires", "")
    if expires not in EXPIRY_CHOICES:
        abort(400, "expires must be one of: " + ", ".join(EXPIRY_CHOICES))
    max_downloads_raw = request.form.get("max_downloads", "")
    # ASCII digits only. str.isdigit() would also accept "²" or "٣", which int() then rejects or
    # misreads; this also rejects "1.5", "-1", " 3" and "1e1".
    if not MAX_DOWNLOADS_PATTERN.fullmatch(max_downloads_raw) or int(max_downloads_raw) not in MAX_DOWNLOADS_RANGE:
        abort(400, "max_downloads must be a whole number from 1 to 10.")
    max_downloads = int(max_downloads_raw)

    blob = request.files.get("blob")
    if blob is None:
        abort(400, "Missing 'blob' (the encrypted file).")
    data = blob.read()
    if len(data) < MIN_BLOB_SIZE:
        abort(400, "Upload is too small to be an encrypted file.")

    db.purge_if_due()  # opportunistic cleanup (throttled); never fails the upload
    reservation = reserve_upload(len(data))

    # 128 random bits: unguessable, so ids can't be enumerated to find other people's files.
    file_id = secrets.token_urlsafe(16)
    delete_token = secrets.token_urlsafe(32)
    created = db.now()
    expires_at = created + EXPIRY_CHOICES[expires]

    # Write to a temporary name, move it into place, and only then insert the row. A download can
    # never find a row whose blob is missing or half-written; a crash at any point leaves at worst
    # an unreferenced blob, which the purge sweep removes.
    final = db.blob_path(file_id)
    tmp = final + ".part"
    try:
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, final)
        except BaseException:
            # e.g. the disk is full: don't leave a partial file lying around until the next sweep.
            try:
                os.remove(tmp)
            except FileNotFoundError:
                pass
            raise
        try:
            db.get_db().execute(
                "INSERT INTO files (id, delete_token_hash, size, created_at, expires_at, max_downloads)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (file_id, hash_token(delete_token), len(data), created, expires_at, max_downloads),
            )
        except BaseException:
            db.remove_blob(file_id)
            raise
    except Exception:
        # Nothing was stored, so it shouldn't count against the visitor. If giving it back fails
        # too, log that and let the original error propagate rather than be masked.
        try:
            release_upload(reservation)
        except Exception:  # noqa: BLE001
            current_app.logger.exception("could not release upload reservation %s", reservation)
        raise

    return jsonify(id=file_id, delete_token=delete_token, expires_at=expires_at), 201


def delete_if_expired(file_id: str) -> bool:
    """Delete one file if it has expired (cheaper than a full purge). Returns True if it was expired."""
    with db.immediate_transaction() as conn:
        gone = conn.execute("DELETE FROM files WHERE id = ? AND expires_at <= ?", (file_id, db.now())).rowcount
    if gone:
        db.remove_blob(file_id)
    return bool(gone)


@bp.get("/<file_id>/info")
def info(file_id: str):
    """Expiry and downloads left. Read-only: this never uses up a download."""
    require_valid_id(file_id)
    row = db.get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        abort(404, NOT_FOUND)
    if row["expires_at"] <= db.now():
        delete_if_expired(file_id)
        abort(410, "This link has expired.")
    return jsonify(
        expires_at=row["expires_at"],
        downloads_left=downloads_left(row),
        max_downloads=row["max_downloads"],
        size=row["size"],
    )


@bp.get("/<file_id>")
def download(file_id: str):
    """Return the ciphertext and count one download, atomically."""
    # Flask answers HEAD with the GET view. Here that would count a download (and destroy a
    # one-time file) for a request that never receives the body, e.g. from a link checker.
    if request.method != "GET":
        raise MethodNotAllowed(valid_methods=["GET", "DELETE"], description="Use GET to download.")
    require_valid_id(file_id)

    # Cheap read-only check first, so requests for random or already-used ids are answered without
    # taking the database write lock that uploads, deletes and real downloads need.
    if db.get_db().execute("SELECT 1 FROM files WHERE id = ?", (file_id,)).fetchone() is None:
        abort(404, NOT_FOUND)

    # BEGIN IMMEDIATE takes SQLite's write lock *before* reading. Two simultaneous requests for a
    # one-time file are therefore serialised: the second waits, then finds the row already gone.
    # With a plain BEGIN, both could read "1 download left" before either wrote, and both succeed.
    blob = None
    left = 0
    expired = False
    try:
        with db.immediate_transaction() as conn:
            # Everything is (re-)checked under the lock: another request may have used the file up
            # since the check above, or it may have expired in the meantime.
            row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
            if row is not None and row["expires_at"] <= db.now():
                conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
                expired = True
            elif row is not None:
                try:
                    # Open (not read) while holding the lock: this claims the blob for this request.
                    # The slow part, reading up to 25 MB, happens after COMMIT so other requests
                    # aren't stuck waiting on the database lock meanwhile.
                    blob = open(db.blob_path(file_id), "rb")
                except FileNotFoundError:
                    # Row without a blob (e.g. disk cleaned by hand). Nothing to serve; drop the row.
                    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
                else:
                    left = downloads_left(row) - 1
                    if left <= 0:
                        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
                    else:
                        conn.execute("UPDATE files SET downloads = downloads + 1 WHERE id = ?", (file_id,))
    except BaseException:
        if blob is not None:
            blob.close()
        raise
    if expired:
        db.remove_blob(file_id)
        abort(410, "This link has expired.")
    if blob is None:
        abort(404, NOT_FOUND)

    # Trade-off: the download is already counted, so if this read fails (I/O error, out of memory)
    # that download is lost. The alternative, reading under the lock, blocks every other writer.
    with blob:
        data = blob.read()
    if left <= 0:
        # After COMMIT and after reading: if we crash first, the purge sweep removes the orphan.
        db.remove_blob(file_id)

    response = Response(data, mimetype="application/octet-stream")
    response.headers["X-Downloads-Left"] = str(left)
    return response


@bp.delete("/<file_id>")
def delete(file_id: str):
    require_valid_id(file_id)
    token = request.headers.get("X-Delete-Token", "")
    if not token:
        abort(401, "Missing X-Delete-Token header.")

    with db.immediate_transaction() as conn:
        row = conn.execute("SELECT delete_token_hash FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            abort(404, NOT_FOUND)
        # compare_digest takes the same time however many leading characters match, so response
        # timing can't be used to guess the stored hash one character at a time.
        if not hmac.compare_digest(hash_token(token), row["delete_token_hash"]):
            abort(403, "Wrong delete token.")
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.remove_blob(file_id)
    return "", 204
