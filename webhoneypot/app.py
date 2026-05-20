import base64
import json
import os
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, g

app = Flask(__name__)

DB_PARAMS = {
    "host":     os.environ.get("POSTGRES_HOST", "127.0.0.1"),
    "port":     int(os.environ.get("POSTGRES_PORT", 5432)),
    "dbname":   os.environ.get("POSTGRES_DB", "cowrie"),
    "user":     os.environ.get("POSTGRES_USER", "cowrie"),
    "password": os.environ.get("POSTGRES_PASSWORD", ""),
}

_SKIP_HEADERS = {"host", "connection", "x-real-ip", "x-forwarded-for", "x-forwarded-proto"}

# Bots POST credentials under many field names; normalise into username/password
# so the stats queries (which look up form_data->>'username'/'password') see them.
_USERNAME_KEYS = ("username", "user", "login", "uname", "name", "email", "userid", "user_id", "j_username")
_PASSWORD_KEYS = ("password", "pass", "passwd", "pwd", "passwort", "j_password")


def _db():
    if "db" not in g:
        g.db = psycopg2.connect(**DB_PARAMS)
        g.db.autocommit = True
    return g.db


@app.teardown_appcontext
def _close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _real_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _safe_headers():
    return {
        k: v for k, v in request.headers
        if k.lower() not in _SKIP_HEADERS
    }


def _log_visit():
    try:
        cur = _db().cursor()
        cur.execute(
            """
            INSERT INTO web_visits
                (ip, method, path, query_string, user_agent, referrer, headers)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                _real_ip(),
                request.method,
                request.path,
                request.query_string.decode("utf-8", errors="replace"),
                request.headers.get("User-Agent", ""),
                request.headers.get("Referer", ""),
                json.dumps(_safe_headers()),
            ),
        )
        g.visit_id = cur.fetchone()[0]
    except Exception:
        g.visit_id = None


def _basic_auth_creds():
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(auth[6:].strip(), validate=False).decode("utf-8", errors="replace")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    u, p = decoded.split(":", 1)
    return u, p


def _capture_credentials():
    creds = {}

    if request.form:
        for k, v in request.form.items():
            creds[k] = v
    elif request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (str, int, float, bool)):
                    creds[str(k)] = str(v)

    basic = _basic_auth_creds()
    if basic:
        creds.setdefault("username", basic[0])
        creds.setdefault("password", basic[1])

    if not creds:
        return

    if "username" not in creds:
        for k in _USERNAME_KEYS:
            if creds.get(k):
                creds["username"] = creds[k]
                break
    if "password" not in creds:
        for k in _PASSWORD_KEYS:
            if creds.get(k):
                creds["password"] = creds[k]
                break

    visit_id = getattr(g, "visit_id", None)
    try:
        cur = _db().cursor()
        cur.execute(
            "INSERT INTO web_form_submissions (visit_id, form_data) VALUES (%s, %s)",
            (visit_id, json.dumps(creds)),
        )
    except Exception:
        pass


@app.before_request
def before_request():
    _log_visit()
    _capture_credentials()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", error=None)


@app.route("/login", methods=["POST"])
def login():
    return render_template("index.html", error="Invalid username or password.")


@app.route("/<path:p>", methods=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"])
def catchall(p):
    return render_template("404.html"), 404
