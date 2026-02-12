#!/bin/sh
# Merge system CA bundle with Ziti controller CA (if present) so the Go SDK
# trusts the self-signed Ziti controller certificate during OIDC auth flow.

COMBINED_CA="/tmp/ca-bundle.crt"
SYSTEM_CA="/etc/ssl/certs/ca-certificates.crt"
ZITI_CA="/ziti/ca.pem"

if [ -f "$ZITI_CA" ]; then
  cat "$SYSTEM_CA" "$ZITI_CA" > "$COMBINED_CA" 2>/dev/null
  export SSL_CERT_FILE="$COMBINED_CA"
  echo "Merged Ziti CA into SSL_CERT_FILE=$COMBINED_CA"
fi

exec /app/service "$@"
