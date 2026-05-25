import gzip
import hashlib
import io
import os
import requests
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

# Federation admin panel (mounted at /admin/).
from admin import bp as admin_bp  # noqa: E402
app.register_blueprint(admin_bp)


RECAPTCHA_SEC   = os.environ.get("RECAPTCHA_SECRET_KEY", "")
RECAPTCHA_SITE  = os.environ.get("RECAPTCHA_SITE_KEY", "")
RECAPTCHA_SCORE = float(os.environ.get("RECAPTCHA_MIN_SCORE", "0.5"))

STATS_DIR = os.environ.get("STATS_DIR", "/stats")

WINDOWS = {"1h", "6h", "24h", "7d", "30d", "all"}


@app.route("/")
def index():
    return render_template("index.html", recaptcha_site_key=RECAPTCHA_SITE)


@app.route("/api/verify-captcha", methods=["POST"])
def verify_captcha():
    if not RECAPTCHA_SEC:
        return jsonify({"success": True})
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    if not token:
        return jsonify({"success": False}), 400
    resp = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": RECAPTCHA_SEC, "response": token},
        timeout=10,
    )
    body = resp.json()
    ok = bool(body.get("success")) and float(body.get("score", 0)) >= RECAPTCHA_SCORE
    return jsonify({"success": ok})


@app.route("/api/stats")
def stats():
    window = request.args.get("window", "6h")
    if window not in WINDOWS:
        window = "6h"

    path = os.path.join(STATS_DIR, f"{window}.json")
    try:
        with open(path) as f:
            return app.response_class(f.read(), mimetype="application/json")
    except FileNotFoundError:
        return jsonify({"error": "stats not yet generated, please wait"}), 503


def _fmt_bytes(n):
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/wordlists")

# Maps URL period param -> subdirectory name used by generate-wordlists.py
WL_PERIODS = {
    "daily":   "daily",
    "weekly":  "weekly",
    "monthly": "monthly",
    "all":     "alltime",
}

# Maps URL wtype param -> filename used by generate-wordlists.py
WL_FILES = {
    "usernames":          "usernames.txt",
    "passwords":          "passwords.txt",
    "pairs":              "passwords_usernames.txt",
    "novel_passwords":    "novel_passwords.txt",
    "trending_passwords": "trending_passwords.txt",
    "dying_passwords":    "dying_passwords.txt",
    "hashcat_rules":      "hashcat.rule",
    "john_rules":         "john.rule",
}

RULE_TYPES = {"hashcat_rules", "john_rules"}


def _wl_path(period, wtype):
    return os.path.join(WORDLIST_DIR, WL_PERIODS[period], WL_FILES[wtype])


def _wl_meta(path, skip_comments=False):
    """Return (line_count, file_size, mtime) for a wordlist file, or None if missing."""
    try:
        st = os.stat(path)
        with open(path, "rb") as f:
            count = sum(1 for _ in f)
        return count, st.st_size, st.st_mtime
    except FileNotFoundError:
        return None


def _rule_preview(path, n=5):
    lines = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line and not line.startswith("#") and not line.startswith("["):
                    lines.append(line)
                    if len(lines) >= n:
                        break
    except FileNotFoundError:
        pass
    return lines


WL_OFFSETS = {
    "daily":   timedelta(days=1),
    "weekly":  timedelta(days=7),
    "monthly": timedelta(days=30),
    "all":     None,
}


@app.route("/api/wordlist")
def wordlist_meta():
    period = request.args.get("period", "all")
    if period not in WL_PERIODS:
        period = "all"

    now = datetime.now(timezone.utc)
    offset = WL_OFFSETS[period]
    oldest_iso = (now - offset).isoformat() if offset else None
    newest_iso = now.isoformat()

    def info(wtype):
        path = _wl_path(period, wtype)
        meta = _wl_meta(path)
        if meta is None:
            return {"ready": False, "oldest": None, "newest": None}
        count, size, mtime = meta
        sha = hashlib.sha256(f"{count}:{mtime}".encode()).hexdigest()
        is_rule = wtype in RULE_TYPES
        if is_rule:
            preview_lines = _rule_preview(path)
        else:
            preview_lines = []
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        if i >= 5:
                            break
                        preview_lines.append(line.rstrip("\n"))
            except FileNotFoundError:
                pass
        return {
            "ready":   True,
            "total":   count,
            "oldest":  oldest_iso if not is_rule else None,
            "newest":  newest_iso if not is_rule else None,
            "size":    _fmt_bytes(size),
            "gz_size": _fmt_bytes(int(size * 0.35)),
            "sha256":  sha,
            "preview": preview_lines,
        }

    return jsonify({
        "period":             period,
        "usernames":          info("usernames"),
        "passwords":          info("passwords"),
        "pairs":              info("pairs"),
        "novel_passwords":    info("novel_passwords"),
        "trending_passwords": info("trending_passwords"),
        "dying_passwords":    info("dying_passwords"),
        "hashcat_rules":      info("hashcat_rules"),
        "john_rules":         info("john_rules"),
    })


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not found"}), 404
    return redirect(url_for("index"))


@app.route("/api/wordlist/<wtype>/download")
def wordlist_download(wtype):
    if wtype not in WL_FILES:
        return jsonify({"error": "invalid type"}), 400
    period = request.args.get("period", "all")
    if period not in WL_PERIODS:
        period = "all"

    path = _wl_path(period, wtype)
    if not os.path.exists(path):
        return jsonify({"error": "wordlist not yet generated"}), 503

    if wtype in RULE_TYPES:
        ext = "hashcat.rule" if wtype == "hashcat_rules" else "john.rule"
        with open(path, "rb") as f:
            data = f.read()
        return Response(
            data,
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename=honey_{period}_{ext}"},
        )

    buf = io.BytesIO()
    with open(path, "rb") as f:
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(f.read())
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype="application/gzip",
        headers={"Content-Disposition": f"attachment; filename=honey_{period}_{wtype}.txt.gz"},
    )

