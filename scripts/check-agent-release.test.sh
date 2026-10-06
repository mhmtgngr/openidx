#!/usr/bin/env bash
# Self-test for check-agent-release.sh: each case undoes one half of the fix in
# a copy of the repository and asserts the guard notices.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-agent-release.sh"

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

stage() { # a pristine copy of what the guard reads
  T="$TMP/repo"; rm -rf "$T"; mkdir -p "$T/.github/workflows"
  cp "$ROOT/.github/workflows/windows-client-build.yml" "$T/.github/workflows/"
  cp -r "$ROOT/agent" "$T/agent"
}
WF() { echo "$T/.github/workflows/windows-client-build.yml"; }

stage
expect ok "the real tree passes"

stage
sed -i 's/^      release:$/      unused:/' "$(WF)"
expect red "no release dispatch input"

stage
sed -i 's/tag="agent-v$INPUT_VERSION"/tag="$INPUT_VERSION"/' "$(WF)"
expect red "dispatch names no agent-v tag"

stage
sed -i 's/tag_name: ${{ steps.ver.outputs.tag }}/tag_name: ${{ github.ref_name }}/' "$(WF)"
expect red "published under the ref, not the tag"

stage
sed -i '0,/GH_REF_NAME: ${{ steps.ver.outputs.tag }}/s//GH_REF_NAME: ${{ github.ref_name }}/' "$(WF)"
expect red "a release step reads github.ref_name"

stage
sed -i 's/make_latest: false/make_latest: true/' "$(WF)"
expect red "an agent release takes latest"

stage
sed -i 's/gh release upload "$AGENT_CHANNEL" --clobber/echo skip/' "$(WF)"
expect red "the channel is not updated"

stage
sed -i 's/updater.DefaultManifestURL=$AGENT_CHANNEL_MANIFEST/updater.Unused=$AGENT_CHANNEL_MANIFEST/' "$(WF)"
expect red "release builds carry no channel"

stage
sed -i 's/(-d "DefaultManifestURL=$AGENT_CHANNEL_MANIFEST")/()/' "$(WF)"
expect red "the MSI does not default to the channel"

stage
sed -i 's#releases/download/agent-latest/latest.json#releases/latest/download/latest.json#' "$T/agent/scripts/install-openidx-agent.ps1"
expect red "the install script points at releases/latest again"

stage
sed -i "s/\$src.Replace('__SERVER_URL__', \$server)/\$src.Replace('__ENROLL_TOKEN__', \$env:T).Replace('__SERVER_URL__', \$server)/" "$(WF)"
expect red "the install script is stamped with a token again"

stage
sed -i 's/^          DEFAULT_SERVER_IP: ${{ vars.AGENT_DEFAULT_SERVER_IP }}$/&\n          DEFAULT_ENROLL_TOKEN: ${{ vars.AGENT_DEFAULT_ENROLL_TOKEN }}/' "$(WF)"
expect red "the stamp step reads a token variable"

stage
sed -i 's/a published script must carry no enrollment token/ok/' "$(WF)"
expect red "the stamp step no longer asserts the placeholder"

stage
sed -i 's/= "__ENROLL_TOKEN__",/= "0123456789abcdef",/' "$T/agent/scripts/install-openidx-agent.ps1"
expect red "the script's own -Token default is a literal"

echo "check-agent-release.test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
