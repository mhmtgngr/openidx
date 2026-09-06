#!/usr/bin/env bash
# Guard: every artifact that declares a version declares the SAME one.
#
# Before the VERSION file existed, the tree carried five answers to "what
# version is this?": the console said 1.27.0, the Helm chart's appVersion said
# 0.1.0, the Flutter client said 1.33.2, all ten OpenAPI specs said 0.1.0, and
# the last actual release was v1.33.3. None of them was wrong on purpose —
# each simply moved on its own, because nothing compared them. A version that
# nobody keeps is a version nobody can trust, and this is a product whose
# users are told to verify signatures against a release number.
#
# VERSION at the repo root is now the single answer. This checks the rest
# against it.
#
# Deliberately NOT checked:
#   - Chart.yaml `version:` — the CHART's own version, which by Helm convention
#     moves when the templates change, not when the app does. appVersion is the
#     one that tracks the app, and that IS checked.
#   - agent/Makefile VERSION — derived from `git describe` at build time, which
#     is the right source for a binary stamped from a tag.
#   - CHANGELOG headings — those record what WAS released; VERSION is what is
#     being built.
#
# Default: report and exit 0. --enforce: exit 1 on any mismatch.
set -uo pipefail
cd "$(dirname "$0")/.."

ROOT="${SH_VERSION_ROOT:-.}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

if [ ! -f "$ROOT/VERSION" ]; then
  echo "offender: $ROOT/VERSION is missing — it is the single source of truth"
  [ "$ENFORCE" = 1 ] && exit 1
  exit 0
fi
WANT=$(tr -d '[:space:]' < "$ROOT/VERSION")
offenders=0
checked=0

report() { echo "offender: $1"; offenders=$((offenders+1)); }
same()   { # same <label> <got>
  checked=$((checked+1))
  [ "$2" = "$WANT" ] || report "$1 is '$2', VERSION says '$WANT'"
}

# The admin console.
f="$ROOT/web/admin-console/package.json"
[ -f "$f" ] && same "$f" "$(sed -n 's/^  "version": "\([^"]*\)".*/\1/p' "$f" | head -1)"

# The Helm chart's appVersion (not its chart version — see the header).
f="$ROOT/deployments/kubernetes/helm/openidx/Chart.yaml"
[ -f "$f" ] && same "$f appVersion" "$(sed -n 's/^appVersion:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$f" | head -1)"

# The Flutter client: `x.y.z+build`, so compare the part before the '+'.
f="$ROOT/client/pubspec.yaml"
if [ -f "$f" ]; then
  got=$(sed -n 's/^version:[[:space:]]*\([^+[:space:]]*\).*/\1/p' "$f" | head -1)
  same "$f" "$got"
fi

# Every OpenAPI spec's info.version.
for f in "$ROOT"/api/openapi/*.yaml; do
  [ -f "$f" ] || continue
  same "$f" "$(sed -n 's/^  version:[[:space:]]*\(.*\)$/\1/p' "$f" | head -1)"
done

echo "version-sync: $offenders offender(s) across $checked declared version(s) (VERSION=$WANT)"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
