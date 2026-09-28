#!/usr/bin/env bash
# Guard: nothing in this repository points at a domain, or a registry or
# GitHub namespace, that the project does not own.
#
# Why this exists: the Helm chart shipped https://auth.openidx.io as the issuer
# and api. and admin. under the same domain as its ingress hosts; the console
# settings defaulted their WebAuthn relying party and support address there;
# Alertmanager mailed it, the welcome email linked to it and the SCIM service
# provider document named its docs host. The project owns none of these names
# (SECURITY.md says so), and anyone can register them. An install that kept the
# defaults sent browsers, sign-in credentials, emailed login links and phones
# to whoever does. The Terraform modules installed the chart from
# oci://ghcr.io/openidx/helm, a registry namespace that is not the project's
# either: whoever holds it chooses what those modules deploy.
#
# What it looks for, in every tracked file:
#   - a host name, an email address or a URL under openidx.io, openidx.org,
#     openidx.com, openidx.net or openidx.dev;
#   - openidx.github.io, the Pages site of a GitHub account that is not the
#     project's;
#   - ghcr.io/openidx and https://github.com/openidx, the same account's
#     registry and repositories. (The Go module path github.com/openidx/openidx
#     is a name the compiler reads, not a URL anything fetches; it is not
#     matched.)
# The project's code is at github.com/mhmtgngr/openidx, its images and chart
# at ghcr.io/mhmtgngr/openidx and its documentation at
# mhmtgngr.github.io/openidx. Examples use example.com or the reserved
# .example, .test and .invalid names (RFC 2606, RFC 6761).
#
# What it leaves alone:
#   - a Kubernetes label key under the openidx.io/ prefix (openidx.io/plane):
#     a name nothing resolves, and one the plane-split Deployments select on,
#     so renaming it would break their immutable selectors on upgrade;
#   - a line that is about the domain rather than a use of it, marked with
#     "domain-ok" and the reason (SECURITY.md saying the domain is not ours,
#     the fixtures that prove the refusals below);
#   - history: CHANGELOG.md, docs/archive/, docs/plans/ and the published
#     advisories record what earlier versions shipped;
#   - scripts/check-third-party-notices.test.sh, whose fixture is go-licenses
#     output for the module path, URL and all;
#   - this script and its self-test.
#
# Usage: scripts/check-unowned-domains.sh [--enforce]
# Default: report and exit 0. --enforce: exit 1 on any offender.
# UNOWNED_DOMAINS_ROOT points it at another checkout (the self-test uses it).
set -uo pipefail

if ! echo x | grep -Pq x 2>/dev/null; then
  echo "FAIL: this check needs GNU grep with -P (PCRE)."
  exit 2
fi

ROOT="${UNOWNED_DOMAINS_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT" || exit 2
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1

# A name under one of the domains, not preceded by a character that would make
# it part of a longer label (evil-openidx.io is someone else's problem) and not
# followed by one that would make it a longer name (openidx.io.example.com) or
# an identifier (openidx.org_slug, a storage key; openidx.org-1.user.created, a
# NATS subject).
HOST='(?<![a-z0-9_-])(?:[a-z0-9-]+\.)*openidx\.(?:io|org|com|net|dev|github\.io)(?![a-z0-9_-]|\.[a-z0-9])'
NAMESPACE='ghcr\.io/openidx(?![a-z0-9-])|https?://(?:www\.)?github\.com/openidx(?![a-z0-9-])'
PATTERN="(?i)(?:$HOST|$NAMESPACE)"
# A label key: the bare domain directly followed by a slash and a name, with
# nothing before it that would make it a host (a dot, an @, a scheme's slash).
LABEL_KEY='(?i)(?<![./@a-z0-9-])openidx\.io/(?=[a-z0-9])'

EXCL=(
  ':!CHANGELOG.md'
  ':!docs/archive/**'
  ':!docs/plans/**'
  ':!docs/security/advisories/**'
  ':!scripts/check-third-party-notices.test.sh'
  ':!scripts/check-unowned-domains.sh'
  ':!scripts/check-unowned-domains.test.sh'
)

offenders=0
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  case "$hit" in *domain-ok*) continue ;; esac
  content="${hit#*:*:}"
  # Drop the label keys, then look again: a line may carry a key and a host.
  # The pattern reaches perl through the environment, so perl does not read
  # the @ in it as an array to interpolate.
  rest=$(printf '%s' "$content" | LK="$LABEL_KEY" perl -pe 's/$ENV{LK}/label-key\//g')
  printf '%s' "$rest" | grep -Pq "$PATTERN" || continue
  echo "offender: $hit"
  offenders=$((offenders+1))
done < <(git grep -n -I -P "$PATTERN" -- . "${EXCL[@]}" 2>/dev/null)

echo "unowned-domain offenders: $offenders"
if [ "$offenders" -gt 0 ]; then
  cat <<'EOF'

  Each line above points at a name the project does not own. Anyone who
  registers it receives what an install sends there.

  Fix by either:
    - leaving the value empty, so the operator must set their own (the Helm
      chart requires config.oauthIssuer for this reason);
    - using example.com, or a reserved .example, .test or .invalid name, in
      an example or a test;
    - pointing at the project's own locations: github.com/mhmtgngr/openidx,
      ghcr.io/mhmtgngr/openidx, mhmtgngr.github.io/openidx;
    - appending "domain-ok: <reason>" to the line if it is about the domain
      rather than a use of it.
EOF
fi
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
