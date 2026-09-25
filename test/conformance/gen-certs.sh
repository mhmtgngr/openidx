#!/usr/bin/env bash
# Makes the TLS material for one conformance run: a throwaway CA, and one
# server certificate it signs for both host names the run uses
# (op.openidx.test and localhost.emobix.co.uk; see compose.yml).
#
# The CA exists so that OpenIDX can verify the suite's certificate when it
# delivers a back-channel logout token: oauth-service is started with ca.crt
# added to its trust bundle (ca-bundle.pem, written next to it). Nothing here
# is committed and nothing outlives the run; the certificates expire in two
# days.
#
# Usage: bash test/conformance/gen-certs.sh <output-directory>
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <output-directory>" >&2
  exit 2
fi
out="$1"
mkdir -p "$out"

subject_alt_names="DNS:op.openidx.test,DNS:localhost.emobix.co.uk"

(
  umask 077
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
    -subj "/CN=OpenIDX conformance run CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$out/ca.key" -out "$out/ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=op.openidx.test" \
    -keyout "$out/tls.key" -out "$out/tls.csr" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    "$subject_alt_names" >"$out/tls.ext"
  openssl x509 -req -in "$out/tls.csr" -CA "$out/ca.crt" -CAkey "$out/ca.key" \
    -CAcreateserial -days 2 -sha256 -extfile "$out/tls.ext" -out "$out/tls.crt" 2>/dev/null
)
rm -f "$out/tls.csr" "$out/tls.ext" "$out/ca.srl"
chmod 644 "$out/ca.crt" "$out/tls.crt"
# The containers read the key through a bind mount as their own root user, so
# it can stay readable by its owner only. The CA key has no further use.
rm -f "$out/ca.key"

# The system roots plus this run's CA, for SSL_CERT_FILE. Go reads the file
# named there INSTEAD of the system bundle, so the system roots are kept.
system_bundle=""
for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
  if [ -f "$candidate" ]; then
    system_bundle="$candidate"
    break
  fi
done
if [ -z "$system_bundle" ]; then
  echo "gen-certs: no system CA bundle found" >&2
  exit 1
fi
cat "$system_bundle" "$out/ca.crt" >"$out/ca-bundle.pem"

openssl verify -CAfile "$out/ca.crt" "$out/tls.crt" >/dev/null
echo "gen-certs: wrote ca.crt, ca-bundle.pem, tls.crt and tls.key to $out"
