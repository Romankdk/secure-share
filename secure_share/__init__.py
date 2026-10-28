"""secure-share: end-to-end encrypted, self-destructing file sharing.

The server in this package never sees a file, a filename or a key. Browsers encrypt files
before upload and decrypt them after download (see static/crypto.js); the server only stores
opaque ciphertext and enforces expiry and download limits.
"""

from __future__ import annotations

import os
import time

from flask import Flask, Response, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db

MiB = 1024 * 1024

# The limit users see is on the file itself. The encrypted upload is slightly bigger: a 12-byte IV,
# a 16-byte GCM tag, the encrypted {name, type} header and multipart framing. Allow for that so a
# file of exactly 25 MB is accepted, while anything meaningfully larger is refused before it is read.
MAX_FILE_SIZE = 25 * MiB
UPLOAD_OVERHEAD = 64 * 1024

# One strict policy for every response. Nothing inline is allowed (no <script> blocks, no style=""
# attributes, no event-handler attributes), so even if an attacker got markup into a page, the
# browser would refuse to run it. frame-ancestors 'none' stops clickjacking by framing, and
# form-action 'self' stops injected markup from posting a form to another site.
CSP = (
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'"
)

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
    # Other sites may not embed our responses (e.g. load ciphertext via <img>/<script>), and pages
    # opened from another site get no handle to this window.
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
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
        # Abuse limits for a public deployment (PythonAnywhere's free tier has 512 MB disk in total):
        UPLOAD_RATE_LIMIT=10,  # uploads per visitor...
        UPLOAD_RATE_WINDOW=3600,  # ...per hour
        VISITOR_DAILY_BYTES=100 * MiB,  # ciphertext one visitor may upload...
        VISITOR_BYTES_WINDOW=86400,  # ...per 24 hours
        STORAGE_QUOTA=300 * MiB,  # total ciphertext kept on disk
        # How many reverse proxies sit in front of the app (PythonAnywhere, Render, nginx: 1).
        # Only then can the visitor's IP be taken from X-Forwarded-For; trusting that header with
        # no proxy in front would let anyone fake their IP and dodge the rate limit.
        TRUSTED_PROXIES=0,
        # Visitor IPs are only stored as HMAC(key, ip). None = load the key from (or create it in)
        # <database folder>/rate_limit.key, so every worker process and every restart agrees on it.
        RATE_LIMIT_KEY=None,
        # SQLite write-ahead logging allows concurrent readers, but needs every process using the
        # database to be on one machine with shared memory. Leave it off on network filesystems
        # such as PythonAnywhere's.
        SQLITE_WAL=False,
    )
    if test_config:
        app.config.update(test_config)

    if app.config["TRUSTED_PROXIES"]:
        n = app.config["TRUSTED_PROXIES"]
        # Only the client IP and the scheme (for HSTS) are needed. Not X-Forwarded-Host: nothing
        # here builds absolute URLs, so trusting a host header would add risk for no benefit.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n)  # type: ignore[method-assign]

    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    if app.config["RATE_LIMIT_KEY"] is None:
        app.config["RATE_LIMIT_KEY"] = db.load_or_create_key(
            os.path.join(os.path.dirname(app.config["DATABASE"]), "rate_limit.key")
        )

    db.init_app(app)

    from . import api, pages

    app.register_blueprint(api.bp)
    app.register_blueprint(pages.bp)

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        if request.is_secure:
            # Once a browser has seen this over HTTPS, it refuses plain HTTP for a year, so nobody
            # on the network can strip HTTPS and serve tampered JavaScript that steals keys.
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.errorhandler(HTTPException)
    def http_error(err: HTTPException):
        # API clients get JSON errors; browsers asking for pages get Flask's plain error page.
        if request.path.startswith("/api/"):
            code = err.code or 500
            message = err.description
            if code == 413 and message == RequestEntityTooLarge.description:
                # Werkzeug's generic text for a body over MAX_CONTENT_LENGTH; say what the limit is.
                message = f"File too large (max {app.config['MAX_FILE_SIZE'] // MiB} MB)."
            response = jsonify(error=message)
            response.status_code = code
            # Keep the protocol headers the exception carries, e.g. Allow on 405, Retry-After on 429.
            for name, value in err.get_headers():
                if name.lower() != "content-type":
                    response.headers[name] = value
            return response
        return err

    return app
