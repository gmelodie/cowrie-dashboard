"""Federation admin panel.

Lives in the existing Flask app under `/admin/`. Reads federation_* tables
directly; for sign-and-send actions (peer request, pull-now) it proxies to
the Rust daemon over loopback at HONEY_DAEMON_INTERNAL_URL.

Auth is enforced here via a session cookie. Credentials are checked against
HONEY_ADMIN_USER + HONEY_ADMIN_PASSWORD_HASH (same htpasswd-style hash the
nginx variant used).
"""

from __future__ import annotations

import base64
import json
import os
import psycopg2
import psycopg2.extras
import requests
from datetime import datetime, timezone
from flask import (
    Blueprint, abort, jsonify, redirect, render_template, request,
    session, url_for,
)
from passlib.hash import apr_md5_crypt

IDENTITY_PREFIX = "honey1:"

bp = Blueprint("admin", __name__, url_prefix="/admin")

DAEMON_INTERNAL_URL = os.environ.get("HONEY_DAEMON_INTERNAL_URL", "http://127.0.0.1:8088")
DAEMON_TIMEOUT_S = 15

ADMIN_USER = os.environ.get("HONEY_ADMIN_USER", "").strip()
ADMIN_HASH = os.environ.get("HONEY_ADMIN_PASSWORD_HASH", "").strip()


# ── Auth ──────────────────────────────────────────────────────────────────────

PUBLIC_ENDPOINTS = {"admin.login", "admin.static"}


@bp.before_request
def _require_login():
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if not session.get("admin_user"):
        return redirect(url_for("admin.login", next=request.path))
    return None


def _verify_password(pwd: str) -> bool:
    if not ADMIN_HASH:
        return False
    try:
        return apr_md5_crypt.verify(pwd, ADMIN_HASH)
    except (ValueError, TypeError):
        return False


def _safe_next(target: str) -> str:
    # Only allow same-origin admin paths to avoid open-redirect abuse.
    if target and target.startswith("/admin/") and "://" not in target:
        return target
    return url_for("admin.dashboard")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_user"):
        return redirect(url_for("admin.dashboard"))

    error, error_key = None, None
    if request.method == "POST":
        user = (request.form.get("username") or "").strip()
        pwd  = request.form.get("password") or ""
        if not ADMIN_USER or not ADMIN_HASH:
            error_key = "a.login.err.config"
            error = "Admin auth is not configured on this server. Set HONEY_ADMIN_USER and HONEY_ADMIN_PASSWORD_HASH."
        elif user != ADMIN_USER or not _verify_password(pwd):
            error_key = "a.login.err.invalid"
            error = "Invalid username or password."
        else:
            session.clear()
            session["admin_user"] = user
            return redirect(_safe_next(request.args.get("next", "")))

    return render_template(
        "admin/login.html",
        error=error,
        error_key=error_key,
        configured=bool(ADMIN_USER and ADMIN_HASH),
    )


@bp.route("/logout", methods=["POST"])
def logout():
    session.pop("admin_user", None)
    return redirect(url_for("admin.login"))


# ── DB helpers (use psycopg2; matches the existing stack) ─────────────────────

def _conn():
    return psycopg2.connect(
        host=os.environ["POSTGRES_HOST"],
        port=os.environ.get("POSTGRES_PORT", "5432"),
        dbname=os.environ["POSTGRES_DB"],
        user=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )


def _query(sql, params=()):
    with _conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()


def _execute(sql, params=()):
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount


def _daemon_info():
    """Best-effort fetch of node identity from the daemon. None if down."""
    try:
        r = requests.get(f"{DAEMON_INTERNAL_URL}/info", timeout=2)
        if r.ok:
            return r.json()
    except requests.RequestException:
        pass
    return None


def _identity_share_string(info) -> str | None:
    """Encode this node's identity into a single copy-pasteable token.

    Format: 'honey1:' + urlsafe-base64(JSON). Peers paste this into their
    add-peer form and the JS auto-fills url/node_name/contact + shows the
    fingerprint for out-of-band verification.
    """
    if not info or not info.get("fingerprint"):
        return None
    payload = {
        "fp":        info["fingerprint"],
        "url":       os.environ.get("HONEY_PUBLIC_URL", "").strip(),
        "node_name": (info.get("node_name") or "").strip(),
        "contact":   (info.get("contact") or "").strip(),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    b64 = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return IDENTITY_PREFIX + b64


# ── Views ─────────────────────────────────────────────────────────────────────

@bp.route("/")
def dashboard():
    info = _daemon_info()
    peers = _query(
        """SELECT fingerprint, node_name, status, local_score,
                  we_approved_them, they_approved_us, last_seen,
                  entries_received, bad_signatures
           FROM federation_peers
           ORDER BY added_at ASC"""
    )
    pending = _query(
        """SELECT fingerprint, node_name, contact, url, description, received_at
           FROM federation_pending_requests
           ORDER BY received_at DESC"""
    )
    fed_count = _query(
        "SELECT COALESCE(SUM(count), 0) AS n FROM federated_wordlist_entries"
    )[0]["n"]
    return render_template(
        "admin/dashboard.html",
        info=info,
        peers=peers,
        pending=pending,
        federated_count=fed_count,
        daemon_url=DAEMON_INTERNAL_URL,
        identity_share=_identity_share_string(info),
    )


@bp.route("/peers")
def peers():
    rows = _query(
        """SELECT * FROM federation_peers ORDER BY added_at ASC"""
    )
    return render_template("admin/peers.html", peers=rows)


@bp.route("/peers/pending")
def pending():
    rows = _query(
        """SELECT * FROM federation_pending_requests ORDER BY received_at DESC"""
    )
    return render_template("admin/pending.html", pending=rows)


@bp.route("/peers/request", methods=["POST"])
def request_peer():
    url = (request.form.get("url") or "").strip()
    node_name = (request.form.get("node_name") or "").strip()
    contact = (request.form.get("contact") or "").strip()
    description = (request.form.get("description") or "").strip()
    if not url:
        return _flash_and_redirect("admin.dashboard", error="url is required")

    try:
        r = requests.post(
            f"{DAEMON_INTERNAL_URL}/internal/peer/request",
            json={
                "url": url,
                "node_name": node_name,
                "contact": contact,
                "description": description,
            },
            timeout=DAEMON_TIMEOUT_S,
        )
        if r.ok:
            return _flash_and_redirect("admin.dashboard", message=f"request sent to {url}")
        return _flash_and_redirect(
            "admin.dashboard", error=f"daemon: {r.status_code} {r.text[:200]}"
        )
    except requests.RequestException as e:
        return _flash_and_redirect("admin.dashboard", error=f"daemon unreachable: {e}")


@bp.route("/peers/<fp>/approve", methods=["POST"])
def approve(fp: str):
    # Move pending → peers in a single transaction; matches the Rust CLI's flow.
    sql = """
    WITH src AS (
        DELETE FROM federation_pending_requests
        WHERE fingerprint = %s
        RETURNING fingerprint, pubkey_b64, url, node_name, contact
    )
    INSERT INTO federation_peers
        (fingerprint, pubkey_b64, url, node_name, contact, status,
         we_approved_them, added_at)
    SELECT s.fingerprint, s.pubkey_b64, s.url, s.node_name, s.contact,
           'trusted', TRUE, NOW()
    FROM src s
    ON CONFLICT (fingerprint) DO UPDATE SET
        pubkey_b64       = EXCLUDED.pubkey_b64,
        url              = EXCLUDED.url,
        node_name        = EXCLUDED.node_name,
        contact          = EXCLUDED.contact,
        status           = 'trusted',
        we_approved_them = TRUE
    """
    n = _execute(sql, (fp,))
    if n == 0:
        return _flash_and_redirect("admin.dashboard", error=f"no pending request {fp}")
    return _flash_and_redirect("admin.dashboard", message=f"approved {fp}")


@bp.route("/peers/<fp>/reject", methods=["POST"])
def reject(fp: str):
    n = _execute(
        "DELETE FROM federation_pending_requests WHERE fingerprint = %s", (fp,)
    )
    if n == 0:
        return _flash_and_redirect("admin.dashboard", error=f"no pending request {fp}")
    return _flash_and_redirect("admin.dashboard", message=f"rejected {fp}")


@bp.route("/peers/<fp>/revoke", methods=["POST"])
def revoke(fp: str):
    purge = request.form.get("purge") in ("1", "true", "on")
    if purge:
        n = _execute("DELETE FROM federation_peers WHERE fingerprint = %s", (fp,))
        msg = f"revoked + purged entries for {fp}"
    else:
        n = _execute(
            "UPDATE federation_peers SET status = 'revoked' WHERE fingerprint = %s",
            (fp,),
        )
        msg = f"revoked {fp}"
    if n == 0:
        return _flash_and_redirect("admin.dashboard", error=f"no peer {fp}")
    return _flash_and_redirect("admin.dashboard", message=msg)


@bp.route("/peers/<fp>/score", methods=["POST"])
def adjust_score(fp: str):
    try:
        delta = int(request.form.get("delta", "0"))
    except ValueError:
        return _flash_and_redirect("admin.dashboard", error="delta must be an int")
    n = _execute(
        """UPDATE federation_peers
           SET local_score = GREATEST(-100, LEAST(100, local_score + %s))
           WHERE fingerprint = %s""",
        (delta, fp),
    )
    if n == 0:
        return _flash_and_redirect("admin.dashboard", error=f"no peer {fp}")
    return _flash_and_redirect("admin.dashboard", message=f"score adjusted {delta:+d} for {fp}")


@bp.route("/peers/<fp>/pull-now", methods=["POST"])
def pull_now(fp: str):
    try:
        r = requests.post(
            f"{DAEMON_INTERNAL_URL}/internal/wordlist/pull-now/{fp}",
            timeout=DAEMON_TIMEOUT_S,
        )
        if r.ok:
            return _flash_and_redirect("admin.dashboard", message=f"pulled from {fp}")
        return _flash_and_redirect(
            "admin.dashboard", error=f"daemon: {r.status_code} {r.text[:200]}"
        )
    except requests.RequestException as e:
        return _flash_and_redirect("admin.dashboard", error=f"daemon unreachable: {e}")


def _flash_and_redirect(endpoint, message=None, error=None):
    qs = {}
    if message:
        qs["m"] = message
    if error:
        qs["e"] = error
    return redirect(url_for(endpoint, **qs))
