#!/usr/bin/env bash
# Self-test for check-unowned-domains.sh. The guard must go red when one of the
# defaults it replaced comes back, in the real file it came from, and on each
# other shape of the same mistake; and it must stay green on the tree as it
# stands and on the names that only look alike. A guard nobody has watched fail
# is a guard nobody can trust, and one that fires on a Kubernetes label key or
# a NATS subject gets switched off.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
GUARD="$REPO/scripts/check-unowned-domains.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fails=0

# run_on <want-exit> <label>: run the guard over the fixture repository in $WORK/repo.
run_on() {
  local want="$1" label="$2" out rc
  ( cd "$WORK/repo" && git add -A >/dev/null 2>&1 )
  out=$(UNOWNED_DOMAINS_ROOT="$WORK/repo" bash "$GUARD" --enforce 2>&1); rc=$?
  if [ "$rc" != "$want" ]; then
    echo "FAIL: $label -- guard exited $rc, expected $want"
    printf '%s\n' "$out" | sed 's/^/    /'
    fails=$((fails+1))
  else
    echo "ok: $label"
  fi
}

# fresh: an empty fixture repository.
fresh() {
  rm -rf "$WORK/repo"; mkdir -p "$WORK/repo"
  git -C "$WORK/repo" init -q
}

# with_line <path> <content>: a fixture repository holding one file with one line.
with_line() {
  fresh
  mkdir -p "$WORK/repo/$(dirname "$1")"
  printf '%s\n' "$2" > "$WORK/repo/$1"
}

# reintroduce <path> <sed expression>: the real file from this tree, with one
# of the old defaults put back. The expression must change the file, or the
# case proves nothing.
reintroduce() {
  fresh
  mkdir -p "$WORK/repo/$(dirname "$1")"
  cp "$REPO/$1" "$WORK/repo/$1"
  sed -i "$2" "$WORK/repo/$1"
  if cmp -s "$REPO/$1" "$WORK/repo/$1"; then
    echo "FAIL: the fixture for $1 did not change it ($2)"; fails=$((fails+1))
  fi
}

# Green: the tree as committed.
if out=$(bash "$GUARD" --enforce 2>&1); then
  echo "ok: the tree as committed passes"
else
  echo "FAIL: the tree as committed is red"; printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails+1))
fi

# Red: each replaced default, put back into the file it was removed from.
reintroduce deployments/kubernetes/helm/openidx/values.yaml 's|  oauthIssuer: ""|  oauthIssuer: "https://auth.openidx.io"|'
run_on 1 "the Helm issuer default is caught"
reintroduce deployments/kubernetes/helm/openidx/values.yaml '0,/    - host: ""/s//    - host: admin.openidx.io/'
run_on 1 "an ingress host default is caught"
reintroduce deployments/kubernetes/helm/openidx/templates/configmap.yaml 's#viteApiUrl | default ""#viteApiUrl | default "https://api.openidx.io"#'
run_on 1 "a configmap fallback is caught"
reintroduce internal/admin/handlers/settings.go '0,/SupportEmail:     "",/s//SupportEmail:     "support@openidx.io",/'
run_on 1 "the console's support address default is caught"
reintroduce internal/admin/handlers/settings.go '0,/RelyingPartyID:       "",/s//RelyingPartyID:       "openidx.io",/'
run_on 1 "the console's relying party default is caught"
reintroduce deployments/docker/alertmanager/alertmanager.yml 's|^  resolve_timeout: 5m|  resolve_timeout: 5m\n  smtp_from: alertmanager@openidx.io|'
run_on 1 "an Alertmanager sender is caught"
reintroduce internal/provisioning/scim_handlers.go 's|https://mhmtgngr.github.io/openidx/guides/SCIM/|https://docs.openidx.io/scim|'
run_on 1 "the SCIM documentation link is caught"
reintroduce deployments/terraform/modules/openziti/variables.tf 's|oci://ghcr.io/mhmtgngr/openidx/charts|oci://ghcr.io/openidx/helm|'
run_on 1 "a chart registry namespace that is not the project's is caught"

# Red: the other shapes of the same mistake.
with_line docs/x.md 'mail admin@openidx.io'
run_on 1 "an email address is caught"
with_line docs/x.md 'see https://openidx.github.io/openidx/api/'
run_on 1 "the other account's Pages site is caught"
with_line docs/api/config.json '"production": "https://api.openidx.org"'
run_on 1 "a host under the .org name is caught"
with_line README.md '[GitHub](https://github.com/openidx/openidx)'
run_on 1 "a link to the other GitHub account is caught"
with_line values.yaml 'host: API.OPENIDX.IO'
run_on 1 "an upper-case name is caught"
with_line values.yaml 'nodeSelector: { openidx.io/plane: issue }, host: api.openidx.io'
run_on 1 "a host on a line that also carries a label key is caught"

# Green: names that only look alike, a marked statement, and history.
with_line values.yaml 'nodeSelector: { openidx.io/plane: issue }'
run_on 0 "a label key is not an address"
with_line ci.yml "--set 'identityService.planeSplit.auth.tolerations[0].key=openidx.io/plane'"
run_on 0 "a toleration keyed by the label is not an address"
with_line x_test.go 'runOrgSlug(t, "example.com", "evil-openidx.io", "")'
run_on 0 "a longer label ending in the name is someone else's"
with_line values.yaml 'oauthIssuer: "https://auth.openidx.example.com"  # and op.openidx.test, noreply@openidx.local, openidx.io.example.com'
run_on 0 "names under example.com and the reserved TLDs pass"
with_line x.go 'Topic: "com.openidx.app"; subject := "openidx.org-1.user.created"; key := "openidx.org_slug"'
run_on 0 "a bundle id, a NATS subject and a storage key are not hosts"
with_line x.go 'import "github.com/openidx/openidx/internal/common/config"'
run_on 0 "the Go module path is not a URL"
with_line SECURITY.md 'Earlier versions listed addresses at `openidx.io`. <!-- domain-ok: says the domain is not ours -->'
run_on 0 "a line marked domain-ok passes"
fresh
mkdir -p "$WORK/repo/docs/archive" "$WORK/repo/docs/security/advisories"
printf 'Fixed: the issuer defaulted to https://auth.openidx.io\n' > "$WORK/repo/CHANGELOG.md"
printf 'The old issuer was https://auth.openidx.io\n' > "$WORK/repo/docs/archive/old.md"
printf 'Installs that kept https://auth.openidx.io\n' > "$WORK/repo/docs/security/advisories/OPENIDX-2026-099.md"
run_on 0 "the changelog, the archive and the advisories may record the old defaults"

if [ "$fails" -gt 0 ]; then
  echo "check-unowned-domains self-test: $fails failure(s)"
  exit 1
fi
echo "check-unowned-domains self-test: all cases behaved"
