#!/usr/bin/env bash
# Arg-parsing / dry-run assertions for connector-install.sh. DRYRUN=1 prints
# the container command instead of running it, so nothing touches docker.
set -euo pipefail
cd "$(dirname "$0")"

fail() { echo "FAIL: $1"; exit 1; }

# A fake docker on PATH so engine detection passes everywhere (incl. CI).
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$tmp/docker"
chmod +x "$tmp/docker"
export PATH="$tmp:$PATH"

# --- private mode (no --advertised): no -p 3022 and no ROUTER_ADVERTISED ---
out=$(DRYRUN=1 bash connector-install.sh --token JWT1 --ctrl ctrl.example.com:1280 --name site-a)
echo "$out" | grep -q 'DRYRUN: docker run -d --name oidx-connector-site-a' || fail "private: container name"
echo "$out" | grep -q -- '--restart=unless-stopped' || fail "private: restart policy"
echo "$out" | grep -q 'site-a-data:/ziti-router' || fail "private: volume"
echo "$out" | grep -q 'ZITI_ENROLL_TOKEN=JWT1' || fail "private: token env"
echo "$out" | grep -q 'ZITI_CTRL_ADVERTISED_ADDRESS=ctrl.example.com' || fail "private: ctrl host"
echo "$out" | grep -q 'ZITI_CTRL_ADVERTISED_PORT=1280' || fail "private: ctrl port"
echo "$out" | grep -q 'ZITI_ROUTER_MODE=host' || fail "private: router mode"
echo "$out" | grep -q 'openziti/ziti-router:' || fail "private: image"
echo "$out" | grep -q -- '-p 3022:3022' && fail "private: MUST NOT publish 3022"
echo "$out" | grep -q 'ZITI_ROUTER_ADVERTISED_ADDRESS' && fail "private: MUST NOT set ROUTER_ADVERTISED_ADDRESS"
echo "OK private (listener-less)"

# --- public mode (--advertised): port published + advertised env set ---
out=$(DRYRUN=1 bash connector-install.sh --token JWT1 --ctrl ctrl.example.com:1280 --name site-b --advertised 192.0.2.7)
echo "$out" | grep -q -- '-p 3022:3022' || fail "public: must publish 3022"
echo "$out" | grep -q 'ZITI_ROUTER_ADVERTISED_ADDRESS=192.0.2.7' || fail "public: advertised env"
echo "$out" | grep -q 'ZITI_ROUTER_PORT=3022' || fail "public: router port env"
echo "OK public (advertised)"

# --- ctrl without a port defaults to 1280 ---
out=$(DRYRUN=1 bash connector-install.sh --token J --ctrl ctrl.example.com --name c)
echo "$out" | grep -q 'ZITI_CTRL_ADVERTISED_PORT=1280' || fail "default ctrl port"
echo "OK default ctrl port"

# --- image tag override ---
out=$(DRYRUN=1 bash connector-install.sh --token J --ctrl c:1 --name c --image-tag 9.9.9)
echo "$out" | grep -q 'openziti/ziti-router:9.9.9' || fail "image tag override"
echo "OK image tag"

# --- uninstall ---
out=$(DRYRUN=1 bash connector-install.sh --name site-a --uninstall)
echo "$out" | grep -q 'DRYRUN: docker rm -f oidx-connector-site-a' || fail "uninstall: rm command"
echo "$out" | grep -q 'site-a-data' || fail "uninstall: must name the kept volume"
echo "OK uninstall"

# --- validation errors ---
out=$(DRYRUN=1 bash connector-install.sh --ctrl c:1 --name c 2>&1 || true)
echo "$out" | grep -q -- '--token is required' || fail "missing token not rejected"
out=$(DRYRUN=1 bash connector-install.sh --token J --name c 2>&1 || true)
echo "$out" | grep -q -- '--ctrl is required' || fail "missing ctrl not rejected"
out=$(DRYRUN=1 bash connector-install.sh --token J --ctrl c:1 2>&1 || true)
echo "$out" | grep -q -- '--name is required' || fail "missing name not rejected"
out=$(DRYRUN=1 bash connector-install.sh --token J --ctrl c:1 --name 'bad name' 2>&1 || true)
echo "$out" | grep -q 'ERROR' || fail "bad name not rejected"
echo "OK validation"

echo "ALL OK"
