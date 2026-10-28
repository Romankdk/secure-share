"""JSON API. Everything here handles ciphertext only; no endpoint can see or produce plaintext."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets

from flask import Blueprint, Response, abort, jsonify, request

from . import db

bp = Blueprint("api", __name__, url_prefix="/api/files")

EXPIRY_CHOICES = {"1h": 3600, "1d": 86400, "7d": 7 * 86400}
MAX_DOWNLOADS_RANGE = range(1, 11)
MAX_DOWNLOADS_PATTERN = re.compile(r"[0-9]{1,2}")

# Smallest possible valid upload: 12-byte IV + 16-byte GCM tag + a 4-byte header length.
MIN_BLOB_SIZE = 12 + 16 + 4


def hash_token(token: str) -> str:
    # Plain SHA-256 is enough here (no slow password hash needed): the token is 256 random bits,
    # so there is nothing to brute-force. Storing only the hash means a leaked database can't be
    # used to delete files.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_valid_id(file_id: str) -> None:
    # Same answer for "malformed" and "doesn't exist", so probing reveals nothing.
    if not db.valid_id(file_id):
        abort(404, "File not found.")


def downloads_left(row) -> int:
    return row["max_downloads"] - row["downloads"]


@bp.post("")
def upload():
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

    db.purge_if_due()  # opportunistic cleanup (throttled), so expired files don't wait for cron

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
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, final)
    try:
        db.get_db().execute(
            "INSERT INTO files (id, delete_token_hash, size, created_at, expires_at, max_downloads)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, hash_token(delete_token), len(data), created, expires_at, max_downloads),
        )
    except BaseException:
        db.remove_blob(file_id)
        raise

    return jsonify(id=file_id, delete_token=delete_token, expires_at=expires_at), 201


@bp.get("/<file_id>/info")
def info(file_id: str):
    """Expiry and downloads left. Read-only: this never uses up a download."""
    require_valid_id(file_id)
    row = db.get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        abort(404, "File not found. It may have been downloaded, deleted or expired.")
    if row["expires_at"] <= db.now():
        db.purge_expired()
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
    require_valid_id(file_id)
    conn = db.get_db()

    # BEGIN IMMEDIATE takes SQLite's write lock *before* reading. Two simultaneous requests for a
    # one-time file are therefore serialised: the second waits, then finds the row already gone.
    # With a plain BEGIN, both could read "1 download left" before either wrote, and both succeed.
    blob = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            abort(404, "File not found. It may have been downloaded, deleted or expired.")

        if row["expires_at"] <= db.now():
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.execute("COMMIT")
            db.remove_blob(file_id)
            abort(410, "This link has expired.")

        try:
            # Open (not read) while holding the lock: this claims the blob for this request.
            # The slow part, reading up to 25 MB, happens after COMMIT so other requests aren't
            # stuck waiting on the database lock meanwhile.
            blob = open(db.blob_path(file_id), "rb")
        except FileNotFoundError:
            # Row without a blob (e.g. disk cleaned by hand). Nothing to serve; drop the row.
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.execute("COMMIT")
            abort(404, "File not found.")

        left = downloads_left(row) - 1
        if left <= 0:
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        else:
            conn.execute("UPDATE files SET downloads = downloads + 1 WHERE id = ?", (file_id,))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        if blob is not None:
            blob.close()
        raise

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

    conn = db.get_db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT delete_token_hash FROM files WHERE id = ?", (file_id,)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            abort(404, "File not found.")
        # compare_digest takes the same time however many leading characters match, so response
        # timing can't be used to guess the stored hash one character at a time.
        if not hmac.compare_digest(hash_token(token), row["delete_token_hash"]):
            conn.execute("ROLLBACK")
            abort(403, "Wrong delete token.")
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    db.remove_blob(file_id)
    return "", 204
