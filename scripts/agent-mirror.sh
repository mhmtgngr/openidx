#!/usr/bin/env bash
# agent-mirror.sh: copy one agent-v* release into the box's update mirror.
#
# Windows agents fetch updates only from the OpenIDX box. This script (run on
# the box) downloads a release's latest.json and the MSI it names from GitHub,
# checks the manifest's signature against the pinned release publisher
# (agent/internal/updater/release-publisher.cer, and -next.cer when present)
# and the MSI against the signed sha256, then installs both into
# $DEST/agent/<channel>/. The access service serves them at
# /downloads/agent/<channel>/latest.json, re-signed with the box URL
# (internal/access/agent_mirror.go). docs/runbooks/agent-updates.md.
#
#   scripts/agent-mirror.sh agent-v1.2.3            # stable
#   scripts/agent-mirror.sh agent-v1.3.0-beta.1     # beta (from the tag)
#
# Settings (environment):
#   DEST       downloads dir (default deployments/downloads; AGENT_DOWNLOADS_DIR)
#   CHANNEL    stable|beta (default: beta for *-beta.* tags, else stable)
#   GH_REPO    owner/repo (default mhmtgngr/openidx)
#   GH_BASE    release download base (default https://github.com/$GH_REPO/releases/download)
#   CERTS      space-separated DER certs to trust (default the pinned ones)
set -euo pipefail

die() { printf 'agent-mirror: ERROR: %s\n' "$*" >&2; exit 1; }
say() { printf 'agent-mirror: %s\n' "$*"; }

TAG=${1:-${AGENT_MIRROR_TAG:-}}
[[ "$TAG" =~ ^agent-v[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]*)?$ ]] || die "usage: $0 agent-vX.Y.Z (got '${TAG}')"
VER=${TAG#agent-v}
here=$(cd "$(dirname "$0")/.." && pwd)
DEST=${DEST:-${AGENT_DOWNLOADS_DIR:-$here/deployments/downloads}}
GH_REPO=${GH_REPO:-mhmtgngr/openidx}
GH_BASE=${GH_BASE:-https://github.com/$GH_REPO/releases/download}
if [ -z "${CHANNEL:-}" ]; then
  case "$VER" in *-beta.*) CHANNEL=beta ;; *) CHANNEL=stable ;; esac
fi
case "$CHANNEL" in stable|beta) ;; *) die "CHANNEL must be stable or beta" ;; esac
if [ -z "${CERTS:-}" ]; then
  CERTS="$here/agent/internal/updater/release-publisher.cer"
  next="$here/agent/internal/updater/release-publisher-next.cer"
  [ -s "$next" ] && CERTS="$CERTS $next"
fi
for c in curl openssl jq sha256sum base64; do command -v "$c" >/dev/null || die "$c is required"; done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say "fetching $TAG/latest.json"
curl -fsSL --proto '=https,file' -o "$work/latest.json" "$GH_BASE/$TAG/latest.json" || die "no latest.json on $TAG"
mver=$(jq -er '.version' "$work/latest.json") || die "latest.json has no version"
murl=$(jq -er '.url' "$work/latest.json") || die "latest.json has no url"
msha=$(jq -er '.sha256' "$work/latest.json" | tr 'A-F' 'a-f') || die "latest.json has no sha256"
msig=$(jq -er '.signature' "$work/latest.json") || die "latest.json is unsigned"
[ "$mver" = "$VER" ] || die "latest.json is for $mver, not $VER"
[[ "$msha" =~ ^[0-9a-f]{64}$ ]] || die "latest.json sha256 is not hex"
msi=${murl##*/}
[[ "$msi" =~ ^[A-Za-z0-9._-]+\.msi$ ]] || die "latest.json names '$msi', not an MSI"

# Canonical signing input: byte for byte updater.signingInput.
printf 'openidx-agent-update-manifest/v1\nversion=%s\nurl=%s\nsha256=%s\n' \
  "$(jq -r .version "$work/latest.json")" "$murl" "$(jq -r .sha256 "$work/latest.json")" >"$work/input"
printf '%s' "$msig" | base64 -d >"$work/sig" 2>/dev/null || die "signature is not base64"
ok=""
for c in $CERTS; do
  [ -s "$c" ] || continue
  openssl x509 -inform DER -in "$c" -checkend 0 -noout >/dev/null 2>&1 || { say "skipping expired or unreadable $c"; continue; }
  openssl x509 -inform DER -in "$c" -pubkey -noout >"$work/pub.pem" 2>/dev/null || continue
  if openssl dgst -sha256 -verify "$work/pub.pem" -signature "$work/sig" "$work/input" >/dev/null 2>&1; then
    ok=$c; break
  fi
done
[ -n "$ok" ] || die "latest.json is not signed by the pinned release publisher ($CERTS)"
say "signature verified against $(basename "$ok")"

say "fetching $msi"
curl -fsSL --proto '=https,file' -o "$work/$msi" "$GH_BASE/$TAG/$msi" || die "no $msi on $TAG"
got=$(sha256sum "$work/$msi" | cut -d' ' -f1)
[ "$got" = "$msha" ] || die "$msi sha256 $got does not match the signed $msha"
say "sha256 verified"

out="$DEST/agent/$CHANNEL"
mkdir -p "$out"
install -m 0644 "$work/$msi" "$out/$msi.tmp" && mv -f "$out/$msi.tmp" "$out/$msi"
# latest.json last, so the served manifest never names an MSI not yet there.
install -m 0644 "$work/latest.json" "$out/latest.json.tmp" && mv -f "$out/latest.json.tmp" "$out/latest.json"
# Older MSIs are kept for rollback (pin + re-mirror); prune beyond the newest 3.
# shellcheck disable=SC2012
ls -1t "$out"/*.msi 2>/dev/null | tail -n +4 | while read -r old; do rm -f -- "$old"; done
say "mirrored $TAG into $out ($CHANNEL)"
