#!/usr/bin/env bash
# Self-test for check-trust-script.sh: each case breaks one half of the trust
# script's copy of the certificate in a scratch tree and asserts the guard notices.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-trust-script.sh"

pass=0; fail=0
expect() { # expect <ok|red> <name> ; tree staged in $T
  local want="$1" name="$2" out rc
  out="$(OPENIDX_REPO_ROOT="$T" bash "$GUARD" 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then
    echo "  ok   $name"; pass=$((pass+1))
  else
    echo "  FAIL $name (rc=$rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

stage() {
  T="$TMP/repo"; rm -rf "$T"; mkdir -p "$T/agent/scripts" "$T/agent/packaging"
  cp "$ROOT/agent/scripts/trust-and-install-openidx-agent.ps1" "$T/agent/scripts/"
  cp "$ROOT/agent/packaging/openidx-codesign.cer" "$T/agent/packaging/"
}
PS1() { echo "$T/agent/scripts/trust-and-install-openidx-agent.ps1"; }

stage
expect ok "the real tree passes"

stage
sed -i "s/^\$PinnedSha256 = '0/\$PinnedSha256 = '1/" "$(PS1)"
expect red "the pin no longer names the certificate"

stage
printf 'another certificate' > "$T/agent/packaging/openidx-codesign.cer"
expect red "the certificate was replaced and the script was not"

stage
awk "/^\\\$CertBase64 = @'\$/{print; getline; sub(/^./, (substr(\$0,1,1)==\"A\")?\"B\":\"A\"); print; next} {print}" "$(PS1)" > "$TMP/x" && mv "$TMP/x" "$(PS1)"
expect red "one character of the embedded certificate changed"

stage
sed -i "/^\$CertBase64 = @'\$/,/^'@\$/{/^\$CertBase64/!{/^'@\$/!d}}" "$(PS1)"
expect red "the embedded certificate is empty"

stage
rm "$(PS1)"
expect red "the script is missing"

echo "check-trust-script.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
