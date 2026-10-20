#!/usr/bin/env bash
# Guard: the hand-install trust script trusts exactly the certificate the agent
# is signed with.
#
# agent/scripts/trust-and-install-openidx-agent.ps1 embeds
# agent/packaging/openidx-codesign.cer and pins its SHA-256, and puts it in a
# machine's Root and TrustedPublisher stores. When the signing certificate is
# replaced (renewal, or a move to a public one), a stale copy would leave every
# machine set up by the script trusting the old key and still warning on the
# new MSI. This compares the embedded certificate and the pin with the file.
#
# Usage: scripts/check-trust-script.sh        (exit 1 on any mismatch)
# OPENIDX_REPO_ROOT overrides the tree it reads (used by the .test.sh).
set -euo pipefail

ROOT="${OPENIDX_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PS1="$ROOT/agent/scripts/trust-and-install-openidx-agent.ps1"
CER="$ROOT/agent/packaging/openidx-codesign.cer"

fail() { echo "check-trust-script: $*" >&2; exit 1; }

[ -f "$PS1" ] || fail "$PS1 is missing"
[ -f "$CER" ] || fail "$CER is missing"

want_sha="$(sha256sum "$CER" | awk '{print toupper($1)}')"

pin="$(sed -n "s/^\$PinnedSha256 = '\([0-9A-Fa-f]*\)'.*/\1/p" "$PS1")"
[ -n "$pin" ] || fail "no \$PinnedSha256 line in $PS1"
[ "$pin" = "$want_sha" ] || fail "\$PinnedSha256 is $pin but $CER hashes to $want_sha"

embedded="$(awk "/^\\\$CertBase64 = @'\$/{f=1;next} /^'@\$/{f=0} f" "$PS1" | tr -d ' \r\n')"
[ -n "$embedded" ] || fail "no embedded certificate between \$CertBase64 = @' and '@ in $PS1"
got_sha="$(printf '%s' "$embedded" | base64 -d 2>/dev/null | sha256sum | awk '{print toupper($1)}')"
[ "$got_sha" = "$want_sha" ] || fail "the embedded certificate hashes to $got_sha, not $CER ($want_sha); re-embed it with: base64 -w 76 $CER"

echo "check-trust-script: the trust script embeds and pins $CER ($want_sha)"
