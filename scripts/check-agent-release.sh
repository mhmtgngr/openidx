#!/usr/bin/env bash
# Guard: the Windows agent can be released, and installed agents can find it.
#
# WHY: two defects kept every agent fix of September and October 2026 away from
# the machines it was for.
#
#   1. The agent was released only by pushing an agent-v* tag, and a session
#      whose git credential is scoped to branches gets 403 on refs/tags/*. So
#      the agent went unreleased for eleven weeks while its fixes merged:
#      agent-v0.2.9 (2026-07-20) stayed the newest MSI anyone could install.
#   2. Every default pointed at releases/latest/download/: the MSI's suggested
#      update_manifest_url, the install script's fallbacks, the docs. GitHub's
#      "latest" is the newest release of ANY kind, and the server is released far
#      more often than the agent, so that URL named a server release with no
#      latest.json and no MSI. Every agent's update check answered 404, and the
#      unstamped install script downloaded nothing.
#
# So this checks that:
#   a. windows-client-build.yml can be dispatched as a release, creates the
#      tag it publishes, and publishes under that tag rather than the ref;
#   b. an agent release never takes "latest" from the server line;
#   c. each release replaces the assets of the agent-latest channel release;
#   d. release builds carry that channel as their default manifest URL;
#   e. nothing under agent/ or in the workflow points a URL at
#      releases/latest/download again;
#   f. the published install script carries no enrollment token. The repository
#      is public, so its release assets are too, and agent-v0.3.0 shipped a
#      reusable token stamped from a repository variable: anyone who downloaded
#      the script could enrol a machine into the organization.
#
# Usage: check-agent-release.sh [--enforce]   (non-zero on a finding either way)
#
# OPENIDX_REPO_ROOT overrides the repository root (used by the .test.sh).
set -euo pipefail

ROOT="${OPENIDX_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
wf="$ROOT/.github/workflows/windows-client-build.yml"

fail=0
finding() {
  printf 'check-agent-release: %s\n' "$1" >&2
  fail=1
}

if [ ! -f "$wf" ]; then
  finding "no workflow at $wf"
  exit 1
fi
body="$(cat "$wf")"

# a. Dispatchable as a release, creating its own tag, publishing under it.
grep -qE '^      release:$' <<<"$body" ||
  finding "windows-client-build.yml takes no 'release' dispatch input, so only a pushed agent-v* tag can release the agent"
grep -qF 'tag="agent-v$INPUT_VERSION"' <<<"$body" ||
  finding "the dispatched release does not name its agent-v<version> tag"
grep -qF 'tag_name: ${{ steps.ver.outputs.tag }}' <<<"$body" ||
  finding "the release is not published under the resolved tag; on a dispatch github.ref_name is the branch"
grep -qF 'GH_REF_NAME: ${{ github.ref_name }}' <<<"$body" &&
  finding "a release step still reads github.ref_name, which on a dispatch names the branch, not the tag"

# b. Never "latest".
grep -qE '^ +make_latest: false$' <<<"$body" ||
  finding "agent releases are not published with make_latest: false, so each one would take 'latest' from the server line"

# c. The channel.
grep -qE '^ +AGENT_CHANNEL: agent-latest$' <<<"$body" ||
  finding "the workflow names no agent-latest release channel"
grep -qF 'gh release upload "$AGENT_CHANNEL" --clobber' <<<"$body" ||
  finding "a release does not replace the agent-latest channel's assets, so agents polling it never see it"

# d. Release builds know their channel.
grep -qF 'updater.DefaultManifestURL=$AGENT_CHANNEL_MANIFEST' <<<"$body" ||
  finding "release builds are not stamped with the channel, so a device enrolled from the console's link never updates"
grep -qF 'DefaultManifestURL=$AGENT_CHANNEL_MANIFEST' <<<"$(grep -A3 'CHANNEL_ARG=(' "$wf" || true)" ||
  finding "the release MSI does not default UPDATE_MANIFEST_URL to the channel"

# e. No URL at releases/latest/download for the agent.
if hits=$(grep -rnE 'https://github\.com/[^[:space:]"]*/releases/latest/download/' \
            "$ROOT/agent" "$wf" 2>/dev/null); then
  while IFS= read -r h; do
    finding "points at releases/latest/download, which is a server release: ${h#"$ROOT"/}"
  done <<<"$hits"
fi

# f. No enrollment token in a published asset.
stamp="$(awk '/^      - name: Stamp install script$/{f=1;print;next} f&&/^      - name:/{exit} f' "$wf")"
if [ -z "$stamp" ]; then
  finding "the workflow has no 'Stamp install script' step, so nothing shows the published script is token-free"
else
  grep -qF "Replace('__ENROLL_TOKEN__'" <<<"$stamp" &&
    finding "the install script is stamped with an enrollment token; the release asset is public"
  grep -qE '\$\{\{ *(vars|secrets)\.[A-Za-z0-9_]*TOKEN' <<<"$stamp" &&
    finding "the stamp step reads a token from vars/secrets; nothing it reads may reach a public asset"
  grep -qF 'a published script must carry no enrollment token' <<<"$stamp" ||
    finding "the stamp step no longer fails when the script's -Token default stops being the placeholder"
fi
grep -qE '^ +\[string\]\$Token +=  *"__ENROLL_TOKEN__",$' "$ROOT/agent/scripts/install-openidx-agent.ps1" ||
  finding "install-openidx-agent.ps1's -Token default is not the __ENROLL_TOKEN__ placeholder"

if [ "$fail" -eq 0 ]; then
  echo "check-agent-release: ok — the agent is releasable by dispatch, agents poll the agent-latest channel, and no token is published"
fi
exit "$fail"
