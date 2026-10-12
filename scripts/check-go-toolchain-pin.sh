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
WORKFLOWS="${CHECK_GO_TOOLCHAIN_FILES:-.github/workflows/ci.yml .github/workflows/display-equals-enforcement.yml .github/workflows/saml-interop.yml .github/workflows/oidc-conformance.yml .github/workflows/helm.yml}"

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

    # A go-version-file must name a file that is there. A typo installs
    # whatever setup-go falls back to and says nothing.
    while IFS= read -r hit; do
        LINE="${hit%%:*}"
        REF=$(echo "$hit" | sed 's/^[0-9]*: *//; s/.*go-version-file: *//; s/[[:space:]]*$//')
        [ -f "$REF" ] && continue
        FINDINGS=$((FINDINGS + 1))
        echo "$wf:$LINE: go-version-file names '$REF', which does not exist"
        # Anchored so the prose in this file's own header -- which names the
        # key it is about -- is not read as a step input.
    done < <(grep -n '^[[:space:]]*go-version-file:' "$wf")

    # A step that runs go in another module must be preceded by a setup-go that
    # reads THAT module's go.mod. go-version-file reads the `go` directive and
    # not `toolchain`, and Go only ever switches UP: a module pinned lower than
    # the installed toolchain is silently analysed against the newer standard
    # library. That is how the agent came to be scanned against go1.26.0 and
    # govulncheck reported 19 advisories fixed in 1.26.1.
    while IFS= read -r hit; do
        LINE="${hit%%:*}"
        MOD=$(echo "$hit" | sed 's/.*working-directory: *//; s/[[:space:]]*$//')
        [ -f "$MOD/go.mod" ] || continue
        grep -qE "^[[:space:]]*go-version-file: *$MOD/go\.mod" "$wf" && continue
        FINDINGS=$((FINDINGS + 1))
        echo "$wf:$LINE: runs in module '$MOD' with no 'go-version-file: $MOD/go.mod' in this workflow"
        echo "    $MOD/go.mod pins its own toolchain; without its own setup-go step it is"
        echo "    analysed against whichever Go the root pin installed."
    done < <(grep -n '^[[:space:]]*working-directory: *[a-z]' "$wf")

    # The cache, and the version that keeps it restorable. Three rules, one
    # incident: restores of setup-go's cache failed with
    #
    #     /usr/bin/tar: ../../../go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.linux-amd64/...:
    #         Cannot open: File exists
    #
    # on Unit Tests, Race Detector and others (2026-10-10/11). setup-go@v5 reads
    # the `go` line (1.26.0), its own `go env GOMODCACHE` then downloaded the
    # pinned toolchain INTO ~/go/pkg/mod, and the restore of an archive already
    # holding that directory collided with it; when the download itself failed,
    # setup failed on `go env`. A second actions/cache over the same paths
    # restored on top again.
    #
    #   1. setup-go must be v6 or later: v6 installs the `toolchain` line, so
    #      nothing is downloaded into the module cache.
    #   2. No actions/cache step may cover ~/go/pkg/mod or ~/.cache/go-build;
    #      setup-go's own cache owns them (it is on by default).
    #   3. v6 exports GOTOOLCHAIN=local, and under GOTOOLCHAIN=local a LATER
    #      setup-go in the same job reads the `go` line again -- so a second
    #      setup-go in a job must set `GOTOOLCHAIN: auto` in its env.
    while IFS= read -r hit; do
        FINDINGS=$((FINDINGS + 1))
        echo "$wf:$hit"
    done < <(awk '
        function flush(   isgo, iscache) {
            if (step == "") return
            isgo = (step ~ /uses:[[:space:]]*actions\/setup-go@/)
            iscache = (step ~ /uses:[[:space:]]*actions\/cache(\/restore)?@/)
            if (isgo) {
                gocount++
                if (step ~ /setup-go@v[0-5]([^0-9]|$)/ || step ~ /setup-go@[0-9a-f]+[[:space:]]*#[[:space:]]*v[0-5]\./)
                    print stepline ": setup-go older than v6 installs the go.mod `go` line, not its `toolchain`, and the toolchain is then downloaded into the module cache"
                if (gocount > 1 && step !~ /GOTOOLCHAIN:[[:space:]]*["\047]?auto/)
                    print stepline ": a second setup-go in job " job " runs under the GOTOOLCHAIN=local the first exported, so it reads the `go` line; give it env GOTOOLCHAIN: auto"
            }
            if (iscache && step ~ /(go\/pkg\/mod|\.cache\/go-build)/)
                print stepline ": actions/cache over the Go module/build cache duplicates setup-go'"'"'s own cache (restores collide: tar File exists)"
            step = ""
        }
        /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { flush(); job = $1; sub(/:$/, "", job); gocount = 0; next }
        /^[[:space:]]+-[[:space:]]+(name|uses|run|id|if|with|env|working-directory|shell|timeout-minutes|continue-on-error):/ {
            flush(); step = $0; stepline = NR; next
        }
        step != "" { step = step "\n" $0 }
        END { flush() }
    ' "$wf")
done

if [ "$FINDINGS" -eq 0 ]; then
    echo "check-go-toolchain-pin: ok — every setup-go step installs the toolchain its module pins ($TOOLCHAIN at the root)"
    exit 0
fi

echo
echo "check-go-toolchain-pin: $FINDINGS finding(s)." >&2
echo "Each finding names its rule; the comments above each check in this script say why." >&2
[ "$ENFORCE" -eq 1 ] && exit 1
exit 0
