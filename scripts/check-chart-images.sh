#!/usr/bin/env bash
# Guard: every image the Helm chart renders must be one that actually exists.
#
# Two failures this catches, both of which `helm lint` and `helm template` pass
# because an image name is only wrong at pull time:
#
#   1. Registry leak. `global.imageRegistry` belongs to the Bitnami subchart
#      contract — their `common.images.image` prefers the global over each
#      chart's own image.registry. values.yaml held the OpenIDX namespace
#      there, so the bundled PostgreSQL, Redis and Elasticsearch rendered as
#      ghcr.io/mhmtgngr/openidx/bitnami/postgresql:… and a default install
#      could never start its own data plane. OpenIDX images now read
#      `global.openidxRegistry` via the `openidx.imageRegistry` helper.
#
#   2. Relocated Bitnami tags. Bitnami moved every pinned tag out of
#      docker.io/bitnami in August 2025 (the free namespace serves `latest`
#      only); the tags these chart versions pin answer 404 there and 200 under
#      docker.io/bitnamilegacy. A subchart bump that reintroduces a plain
#      `bitnami/<name>:<pinned tag>` puts the install back on a 404.
#
# Rendering-only: no cluster and no registry calls, so it runs anywhere.
# Default: report and exit 0. --enforce: exit 1 on any offender.
set -uo pipefail
cd "$(dirname "$0")/.."

CHART="${CHART_DIR:-deployments/kubernetes/helm/openidx}"
ENFORCE=0; [ "${1:-}" = "--enforce" ] && ENFORCE=1
offenders=0

flag() { echo "offender: $1"; offenders=$((offenders+1)); }

# (3) The helper is the only sanctioned way to name an OpenIDX registry, so a
# template that reaches for the Bitnami global directly is the leak coming back.
while IFS= read -r hit; do
  flag "$hit — use {{ include \"openidx.imageRegistry\" . }}, not the Bitnami global"
done < <(grep -rn 'Values\.global\.imageRegistry' "$CHART/templates" 2>/dev/null | grep -v '_helpers.tpl')

render_and_check() {
  local label="$1"; shift
  local out
  if ! out=$(helm template openidx "$CHART" "$@" 2>&1); then
    flag "$label: helm template failed
$out"
    return
  fi
  while IFS= read -r img; do
    case "$img" in
      # A Bitnami repository under anything but the plain docker.io namespace
      # means someone's registry got prefixed onto it.
      */bitnami/*|*/bitnamilegacy/*)
        case "$img" in
          docker.io/bitnami/*|docker.io/bitnamilegacy/*) ;;
          *) flag "$label: $img — a registry is prefixed onto a Bitnami image" ;;
        esac ;;
    esac
    # A pinned tag under the live namespace is the 404 case. `latest` is all
    # the free namespace still serves, so it is the one legal exception.
    case "$img" in
      docker.io/bitnami/*:latest) ;;
      docker.io/bitnami/*) flag "$label: $img — pinned Bitnami tags live under bitnamilegacy/" ;;
    esac
  done < <(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*image:[[:space:]]*"\{0,1\}\([^"[:space:]]*\)"\{0,1\}[[:space:]]*$/\1/p' | sort -u)
}

# The chart `required`s the datastore passwords whenever the bundled
# PostgreSQL/Redis are enabled — an empty one used to install a stack that
# could not authenticate. Rendering therefore has to supply them; these are
# placeholders for a template that is thrown away, not credentials.
PLACEHOLDER_SECRETS=(
  --set secrets.postgresPassword=render-only-not-a-credential
  --set secrets.redisPassword=render-only-not-a-credential
  --set secrets.encryptionKey=render-only-not-a-credential32b
)

render_and_check "values.yaml" "${PLACEHOLDER_SECRETS[@]}"
render_and_check "values-prod.yaml" -f "$CHART/values-prod.yaml"
render_and_check "values-ci.yaml" -f "$CHART/values-ci.yaml"
# The cell shape layers over values-ci.yaml (job kind-cell) and turns on the
# pooler, the replica architecture and the plane split -- so it names images
# the other files do not (pgcat; the replica's own postgresql image path).
render_and_check "values-ci-cell.yaml" -f "$CHART/values-ci.yaml" -f "$CHART/values-ci-cell.yaml"
# volumePermissions init containers are off by default and pull their own image.
render_and_check "volumePermissions" "${PLACEHOLDER_SECRETS[@]}" \
  --set postgresql.volumePermissions.enabled=true \
  --set redis.volumePermissions.enabled=true \
  --set elasticsearch.volumePermissions.enabled=true
# The transaction pooler is off in every values file above except the cell
# layer, so on its own its image would never be rendered and never be checked. It shipped with a tag that does not
# exist (`1.1.1`; the registry's only released tag is `v1.2.0`) and every
# render-time check passed, because a tag is only wrong at pull time — which is
# the exact failure this script exists to catch.
render_and_check "pgcat" "${PLACEHOLDER_SECRETS[@]}" \
  --set config.rlsMode=local \
  --set pgcat.enabled=true \
  --set pgcat.password=render-only-not-a-credential \
  --set pgcat.adminPassword=render-only-not-a-credential \
  --set pgcat.postgresHost=openidx-postgresql
# Same reason, same shape: the broker is off in every values file above, so its
# image would never be rendered and never be checked. Its tag was read from the
# registry when it was chosen (2.14.6-alpine3.22 exists; `latest` and the
# windows variants are what the repository mostly publishes), and this is what
# keeps that true after the next bump.
render_and_check "nats" "${PLACEHOLDER_SECRETS[@]}" \
  --set nats.enabled=true \
  --set nats.relayPassword=render-only-not-a-credential \
  --set nats.consumerPassword=render-only-not-a-credential
# And the relay, which is off in every values file for the same reason and
# carries its own image. It needs a broker to render at all -- the chart refuses
# otherwise -- so this renders both.
render_and_check "eventRelay" "${PLACEHOLDER_SECRETS[@]}" \
  --set nats.enabled=true \
  --set nats.relayPassword=render-only-not-a-credential \
  --set nats.consumerPassword=render-only-not-a-credential \
  --set eventRelay.enabled=true

echo "chart-image offenders: $offenders"
if [ "$ENFORCE" = 1 ] && [ "$offenders" -gt 0 ]; then exit 1; fi
exit 0
