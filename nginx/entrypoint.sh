#!/bin/sh
set -e

CERT_DIR="/etc/letsencrypt/live/${TARGET_HOST}"
SELFSIGNED_DIR="/etc/nginx/ssl"

# Generate a self-signed cert if LE certs don't exist yet (allows nginx to start
# so certbot can complete the ACME HTTP-01 challenge on port 80)
if [ ! -f "${CERT_DIR}/fullchain.pem" ]; then
    echo "[nginx] No LE cert found for ${TARGET_HOST} — using self-signed bootstrap cert"
    mkdir -p "${SELFSIGNED_DIR}"
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
        -keyout "${SELFSIGNED_DIR}/privkey.pem" \
        -out    "${SELFSIGNED_DIR}/fullchain.pem" \
        -subj   "/CN=${TARGET_HOST}" 2>/dev/null
    export CERT_PATH="${SELFSIGNED_DIR}"
else
    export CERT_PATH="${CERT_DIR}"
fi

# Generate self-signed cert for the catch-all 443 server (avoids leaking TARGET_HOST
# in TLS handshakes to unknown clients)
if [ ! -f "/etc/nginx/ssl/catchall.crt" ]; then
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout /etc/nginx/ssl/catchall.key \
        -out    /etc/nginx/ssl/catchall.crt \
        -subj   "/CN=localhost" 2>/dev/null
fi

# Generate the basic-auth file for /admin/ from HONEY_ADMIN_USER + HONEY_ADMIN_PASSWORD_HASH.
# HONEY_ADMIN_PASSWORD_HASH must be in htpasswd format (use `openssl passwd -apr1`).
if [ -n "${HONEY_ADMIN_USER}" ] && [ -n "${HONEY_ADMIN_PASSWORD_HASH}" ]; then
    echo "${HONEY_ADMIN_USER}:${HONEY_ADMIN_PASSWORD_HASH}" > /etc/nginx/admin.htpasswd
    chmod 640 /etc/nginx/admin.htpasswd
    echo "[nginx] /admin/ basic-auth configured for user '${HONEY_ADMIN_USER}'"
else
    # Sentinel — no creds set, /admin/ stays locked down.
    echo "*:*locked-by-default" > /etc/nginx/admin.htpasswd
    echo "[nginx] HONEY_ADMIN_USER not set — /admin/ will reject all requests" >&2
fi

# Substitute only our env vars; nginx variables like $host stay untouched
envsubst '${TARGET_HOST} ${CERT_PATH}' \
    < /etc/nginx/templates/default.conf.template \
    > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
