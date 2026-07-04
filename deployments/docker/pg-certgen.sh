#!/bin/sh
# Generates a self-signed server cert/key for the compose Postgres into /certs if absent,
# with the ownership+perms Postgres requires: uid 70 = postgres in postgres:16-alpine, and
# the key must be mode 0600 (Postgres refuses a world/group-readable key). Idempotent.
set -e
CERT_DIR=/certs
if [ -f "$CERT_DIR/server.key" ]; then
  echo "pg-certgen: cert already present, skipping"
  exit 0
fi
apk add --no-cache openssl >/dev/null 2>&1 || true
openssl req -new -x509 -days 3650 -nodes \
  -out "$CERT_DIR/server.crt" -keyout "$CERT_DIR/server.key" \
  -subj "/CN=postgres"
chown 70:70 "$CERT_DIR/server.crt" "$CERT_DIR/server.key"
chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"
echo "pg-certgen: generated self-signed cert (CN=postgres)"
