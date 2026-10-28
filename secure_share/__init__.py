"""secure-share: end-to-end encrypted, self-destructing file sharing.

The server in this package never sees a file, a filename or a key. Browsers encrypt files
before upload and decrypt them after download (see static/crypto.js); the server only stores
opaque ciphertext and enforces expiry and download limits.
"""

from __future__ import annotations

import os
import time

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from . import db

MiB = 1024 * 1024

# The limit users see is on the file itself. The encrypted upload is slightly bigger: a 12-byte IV,
# a 16-byte GCM tag, the encrypted {name, type} header and multipart framing. Allow for that so a
# file of exactly 25 MB is accepted, while anything meaningfully larger is refused before it is read.
MAX_FILE_SIZE = 25 * MiB
UPLOAD_OVERHEAD = 64 * 1024

# One strict policy for every response. Nothing inline is allowed (no <script> blocks, no style=""
# attributes, no event-handler attributes), so even if an attacker got markup into a page, the
# browser would refuse to run it. frame-ancestors 'none' stops clickjacking by framing.
CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    # Stop browsers from guessing that a ciphertext download is HTML or script.
    "X-Content-Type-Options": "nosniff",
    # Older browsers that don't understand frame-ancestors.
    "X-Frame-Options": "DENY",
    # The download page URL contains the file id; don't leak it to other sites via the Referer header.
    # (The key is in the #fragment, which browsers never send in Referer anyway.)
    "Referrer-Policy": "no-referrer",
    # Nothing here should sit in a shared or disk cache: not ciphertext, not download counts.
    "Cache-Control": "no-store",
}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.path.join(app.instance_path, "secure_share.sqlite"),
        STORAGE_DIR=os.path.join(app.instance_path, "blobs"),
        MAX_FILE_SIZE=MAX_FILE_SIZE,
        # Werkzeug rejects larger request bodies with 413 before reading them.
        MAX_CONTENT_LENGTH=MAX_FILE_SIZE + UPLOAD_OVERHEAD,
        # Seconds since the epoch. Injectable so tests can move time forward instead of sleeping.
        CLOCK=time.time,
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)

    db.init_app(app)

    from . import api, pages

    app.register_blueprint(api.bp)
    app.register_blueprint(pages.bp)

    @app.after_request
    def add_security_headers(response):
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    @app.errorhandler(HTTPException)
    def http_error(err: HTTPException):
        # API clients get JSON errors; browsers asking for pages get Flask's plain error page.
        if request.path.startswith("/api/"):
            message = err.description
            if err.code == 413:
                message = f"File too large (max {app.config['MAX_FILE_SIZE'] // MiB} MB)."
            return jsonify(error=message), err.code
        return err

    return app
