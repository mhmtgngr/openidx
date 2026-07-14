#!/usr/bin/env bash
#
# Lock down the OpenIDX box's secret-bearing runtime files to owner-only.
#
# The service env files carry plaintext secrets (DB/Guacamole/Ziti passwords,
# JWT secret, encryption key, internal service token). They must never be group-
# or world-readable. Everything runs as the same user (systemd --user), so
# owner-only (0600 files, 0700 dirs/scripts) breaks nothing.
#
# Idempotent — safe to run at every deploy. Override OIDX_HOME if the runtime
# lives elsewhere.
set -euo pipefail

HOME_DIR="${OIDX_HOME:-$HOME}"

# dir : mode
dirs=(
  "$HOME_DIR/.config/oidx:700"
  "$HOME_DIR/oidx-runtime/codesign:700"
)
# file : mode  (0700 for scripts that need +x, 0600 for plain secret files)
files=(
  "$HOME_DIR/oidx-runtime/run-access.sh:700"
  "$HOME_DIR/.config/oidx/common.env:600"
  "$HOME_DIR/oidx-runtime/oidx-ziti/ziti_pwd:600"
  "$HOME_DIR/oidx-runtime/codesign/pfx-password.txt:600"
  "$HOME_DIR/oidx-runtime/codesign/openidx-codesign.pfx:600"
  "$HOME_DIR/oidx-runtime/codesign/key.pem:600"
  "$HOME_DIR/oidx-runtime/codesign/cert.pem:600"
)

apply() {
  local path="${1%%:*}" mode="${1##*:}"
  [ -e "$path" ] || return 0
  local cur; cur="$(stat -c '%a' "$path")"
  if [ "$cur" != "$mode" ]; then
    chmod "$mode" "$path"
    echo "  tightened $path  $cur -> $mode"
  else
    echo "  ok        $path  ($mode)"
  fi
}

echo "Hardening OpenIDX secret file permissions under $HOME_DIR ..."
for d in "${dirs[@]}"; do apply "$d"; done
for f in "${files[@]}"; do apply "$f"; done
echo "Done."
