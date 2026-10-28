"""HTML pages. They only serve static markup; all file handling happens in the browser via the API."""

from flask import Blueprint, abort, render_template

from . import db

bp = Blueprint("pages", __name__)


@bp.get("/")
def index():
    return render_template("index.html")


@bp.get("/f/<file_id>")
def download_page(file_id: str):
    # Deliberately does NOT look up or touch the file. Chat apps (Slack, WhatsApp, iMessage...)
    # fetch links to build previews; if visiting this URL counted a download, the preview bot would
    # burn a one-time link before the recipient ever saw it. A download is only counted when the
    # page's JavaScript calls GET /api/files/<id>, after the user clicks Download.
    if not db.valid_id(file_id):
        abort(404)
    return render_template("download.html")
