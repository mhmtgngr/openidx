#!/usr/bin/env bash
# Every actions/setup-go step that builds the ROOT module must install the exact
# toolchain go.mod pins, by passing go-version-file: go.mod.
#
# Why this is a guard and not a preference. go.mod pins `toolchain go1.26.8`.
# ci.yml asked setup-go for '1.26'. The runner's tool cache holds 1.26.7, so
# setup-go reported
#
#     Found in cache @ /opt/hostedtoolcache/go/1.26.7/x64
#     Successfully set up Go version 1.26
#
# and then the very next `go` command downloaded go1.26.8 from proxy.golang.org
# -- about 70 MB, once per job, unretried, on every run. Twelve jobs did this.
# On 2026-09-06 one of those TLS handshakes timed out and failed
# "Unit Tests (internal/notifications)" before a single test body ran. The job
# looked like a test failure and was a CDN blip on a download that did not need
# to happen.
#
# A loose version spec is invisible in the diff that introduces it and invisible
# in the green run that follows, because the download usually succeeds. That is
# the shape this repo keeps finding: it works until the day it does not, and by
# then nobody remembers the version string was the cause.
#
# Scope: the root module only. agent/ and client/ pin their own toolchains
# (agent/go.mod is on go1.25.13), and their workflows are allowed to name a
# version -- they are checked for having a version at all, not for this file.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENFORCE=0
[ "${1:-}" = "--enforce" ] && ENFORCE=1

TOOLCHAIN=$(grep -E '^toolchain go' go.mod | awk '{print $2}')
if [ -z "$TOOLCHAIN" ]; then
    echo "check-go-toolchain-pin: go.mod has no toolchain directive" >&2
    exit 1
fi

# Workflows that build the root module. client-mobile-* build agent/, which
# pins a different toolchain, so they are out of scope here.
WORKFLOWS="${CHECK_GO_TOOLCHAIN_FILES:-.github/workflows/ci.yml}"

FINDINGS=0
for wf in $WORKFLOWS; do
    [ -f "$wf" ] || continue
    # A setup-go step's inputs are the indented block after `uses:
    # actions/setup-go`. Read the file once and report any `go-version:` that
    # follows one, since the file has no other use for that key.
    while IFS= read -r hit; do
        LINE="${hit%%:*}"
        FINDINGS=$((FINDINGS + 1))
        echo "$wf:$LINE: setup-go is given a version spec instead of go-version-file: go.mod"
        echo "    go.mod pins '$TOOLCHAIN'; a looser spec makes every job download the toolchain."
    done < <(awk '
        /uses:[[:space:]]*actions\/setup-go/ { in_step = 1; next }
        in_step && /^[[:space:]]*go-version:/ { print NR ": " $0; in_step = 0; next }
        in_step && /^[[:space:]]*go-version-file:/ { in_step = 0; next }
        in_step && /^[[:space:]]*-[[:space:]]/ { in_step = 0 }
    ' "$wf")
done

if [ "$FINDINGS" -eq 0 ]; then
    echo "check-go-toolchain-pin: ok — every setup-go step installs the toolchain go.mod pins ($TOOLCHAIN)"
    exit 0
fi

echo
echo "check-go-toolchain-pin: $FINDINGS setup-go step(s) with a loose version." >&2
echo "Replace 'go-version: <spec>' with 'go-version-file: go.mod'." >&2
[ "$ENFORCE" -eq 1 ] && exit 1
exit 0
