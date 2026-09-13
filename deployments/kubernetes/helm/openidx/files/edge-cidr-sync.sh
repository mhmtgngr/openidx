#!/usr/bin/env sh
# edge-cidr-sync — keep the edge provider's published address ranges in the
# services' trusted-proxy list (global-scale plan task 0.2).
#
# Why a job and not a value: the provider changes its ranges on its schedule,
# not on ours. A stale list means a new provider PoP is an untrusted hop, its
# X-Forwarded-For is discarded, and every client behind it collapses into one
# rate-limit bucket. A list that is too wide is worse: a range that is not the
# provider's lets whoever holds it name its own client IP.
#
# Fail-safe by construction: any fetch error, parse error, empty result or
# implausibly short list leaves the CURRENT list untouched and exits non-zero,
# so the Job shows as failed (alert: OpenIDXEdgeCidrSyncFailed) and services
# keep trusting yesterday's provider ranges rather than nothing or everything.
#
# Modes (OUTPUT):
#   configmap  write key OIDX_EDGE_TRUSTED_CIDRS into $CONFIGMAP in $NAMESPACE
#              and, only when the list changed, rolling-restart the deployments
#              matching $RESTART_SELECTOR (env from a ConfigMap is read at pod
#              start). Needs kubectl.
#   file       write the comma-separated list to $OUTPUT_FILE (systemd/compose:
#              source it as OIDX_EDGE_TRUSTED_CIDRS, and feed the same list to
#              seed-edge-routes.sh's EDGE_TRUSTED_CIDRS).
#   stdout     print it.
#
# Providers (PROVIDER):
#   cloudflare       https://api.cloudflare.com/client/v4/ips (ipv4 + ipv6)
#   aws-cloudfront   https://ip-ranges.amazonaws.com/ip-ranges.json, service
#                    CLOUDFRONT (ipv4 + ipv6)
#   static           STATIC_CIDRS as given (for a provider without a feed, or
#                    Azure Front Door where the service tag is applied at the
#                    NSG rather than here)
set -eu

PROVIDER=${PROVIDER:-static}
OUTPUT=${OUTPUT:-stdout}
STATIC_CIDRS=${STATIC_CIDRS:-}
CONFIGMAP=${CONFIGMAP:-openidx-edge-cidrs}
NAMESPACE=${NAMESPACE:-default}
RESTART_SELECTOR=${RESTART_SELECTOR:-app.kubernetes.io/part-of=openidx}
OUTPUT_FILE=${OUTPUT_FILE:-/var/lib/openidx/edge-cidrs.env}
MIN_COUNT=${MIN_COUNT:-}
CURL="curl -fsS --max-time 20 --retry 2"

die() { echo "edge-cidr-sync: $*" >&2; exit 1; }

# Plausibility floor per provider: a feed that suddenly returns two entries is
# a broken feed, not a provider that shrank. (Set outside fetch(): fetch runs
# in a subshell, so an assignment there would never reach the comparison.)
if [ -z "$MIN_COUNT" ]; then
  case "$PROVIDER" in
    cloudflare)     MIN_COUNT=15 ;;
    aws-cloudfront) MIN_COUNT=50 ;;
    static)         MIN_COUNT=1 ;;
    *) die "unknown PROVIDER '$PROVIDER'" ;;
  esac
fi

fetch() {
  case "$PROVIDER" in
    cloudflare)
      $CURL https://api.cloudflare.com/client/v4/ips \
        | jq -r 'select(.success==true) | .result | (.ipv4_cidrs + .ipv6_cidrs)[]' ;;
    aws-cloudfront)
      $CURL https://ip-ranges.amazonaws.com/ip-ranges.json \
        | jq -r '(.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix),
                 (.ipv6_prefixes[] | select(.service=="CLOUDFRONT") | .ipv6_prefix)' ;;
    static)
      [ -n "$STATIC_CIDRS" ] || die "PROVIDER=static needs STATIC_CIDRS"
      printf '%s' "$STATIC_CIDRS" | tr ',' '\n' ;;
  esac
}

# Validate every entry: an IPv4 or IPv6 CIDR (or bare address), nothing else.
# A feed that starts returning HTML, an error object or a wildcard must not be
# written into a list that decides whose X-Forwarded-For is believed.
valid_cidr() {
  echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$' && return 0
  echo "$1" | grep -Eq '^[0-9A-Fa-f:]+(/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$' && echo "$1" | grep -q ':' && return 0
  return 1
}

raw=$(fetch) || die "fetch failed for provider $PROVIDER; keeping the current list"
list=""
count=0
for c in $raw; do
  c=$(printf '%s' "$c" | tr -d ' \r')
  [ -n "$c" ] || continue
  valid_cidr "$c" || die "refusing entry '$c' from $PROVIDER feed (not a CIDR); keeping the current list"
  case "$c" in 0.0.0.0/0|::/0) die "refusing $c: trusting everyone is the failure this list prevents" ;; esac
  list="${list:+$list,}$c"
  count=$((count+1))
done
[ "$count" -ge "$MIN_COUNT" ] || die "only $count entries from $PROVIDER (expected >= $MIN_COUNT); keeping the current list"

case "$OUTPUT" in
  stdout) echo "$list" ;;
  file)
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    tmp="$OUTPUT_FILE.tmp.$$"
    printf 'OIDX_EDGE_TRUSTED_CIDRS=%s\n' "$list" > "$tmp"
    if [ -f "$OUTPUT_FILE" ] && cmp -s "$tmp" "$OUTPUT_FILE"; then rm -f "$tmp"; echo "unchanged ($count entries)"; exit 0; fi
    mv "$tmp" "$OUTPUT_FILE"; echo "updated $OUTPUT_FILE ($count entries)" ;;
  configmap)
    command -v kubectl >/dev/null || die "kubectl not found"
    current=$(kubectl -n "$NAMESPACE" get configmap "$CONFIGMAP" -o jsonpath='{.data.OIDX_EDGE_TRUSTED_CIDRS}' 2>/dev/null || true)
    if [ "$current" = "$list" ]; then echo "unchanged ($count entries)"; exit 0; fi
    kubectl -n "$NAMESPACE" create configmap "$CONFIGMAP" \
      --from-literal=OIDX_EDGE_TRUSTED_CIDRS="$list" \
      --from-literal=PROVIDER="$PROVIDER" \
      --from-literal=SYNCED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    echo "updated configmap $NAMESPACE/$CONFIGMAP ($count entries, was $(printf '%s' "$current" | tr ',' '\n' | grep -c . || true))"
    # Env from a ConfigMap is read at pod start; a changed list needs a roll.
    kubectl -n "$NAMESPACE" rollout restart deployment -l "$RESTART_SELECTOR" ;;
  *) die "unknown OUTPUT '$OUTPUT'" ;;
esac
