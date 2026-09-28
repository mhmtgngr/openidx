#!/usr/bin/env bash
# Self-test for check-audit-ingest-edges.sh: each case reopens audit event
# ingestion at one edge, in a shape that still parses and still serves the
# console, and asserts the guard goes red. The real tree must pass.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-audit-ingest-edges.sh"

pass=0; fail=0
expect() { # expect <ok|red> <name>
  local want="$1" name="$2" out rc
  out="$(OPENIDX_EDGE_ROOT="$T" bash "$GUARD" --enforce 2>&1)"; rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -eq 1 ]; }; then
    echo "  ok   $name"; pass=$((pass+1))
  else
    echo "  FAIL $name (rc=$rc, wanted $want)"; echo "$out" | sed 's/^/       /'; fail=$((fail+1))
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

stage() {
  T="$TMP/root"; rm -rf "$T"; mkdir -p "$T/internal/gateway/routes"
  cp -r "$ROOT/deployments" "$T/"
  cp "$ROOT/internal/gateway/routes/audit.go" "$T/internal/gateway/routes/"
}
edit() { # edit <file under $T> <python statements on s>
  python3 - "$T/$1" "$2" <<'PY'
import sys
p, code = sys.argv[1], sys.argv[2]
s = open(p).read()
before = s
exec(code)
if s == before:
    sys.exit("edit changed nothing in " + p)
open(p, "w").write(s)
PY
}

APISIX=deployments/docker/apisix/apisix.yaml
PROD=deployments/docker/load-production-routes.sh
SEED=deployments/apisix-edge/seed-edge-routes.sh
LITE=deployments/docker/nginx/admin-console.lite.conf
HELM=deployments/kubernetes/helm/openidx/templates

stage
expect ok "the shipped edges hold"

# APISIX standalone file.
stage
edit $APISIX 'i=s.index("  - uris:\n      - /api/v1/audit/events\n"); j=s.index("  # Identity service"); s=s[:i]+s[j:]'
expect red "compose APISIX: the deny route is gone"

stage
edit $APISIX 's=s.replace("    methods:\n      - POST\n    name: deny-audit-ingest", "    methods:\n      - PUT\n    name: deny-audit-ingest")'
expect red "compose APISIX: the deny route catches PUT, not POST"

stage
edit $APISIX 's=s.replace("      - /api/v1/audit/events/\n    methods:", "    methods:")'
expect red "compose APISIX: the trailing-slash path is left to the audit route"

stage
edit $APISIX 's=s.replace("  - uri: /api/v1/audit/*\n    name: audit-service\n", "  - uri: /api/v1/audit-gone/*\n    name: audit-service\n")'
expect red "compose APISIX: the console's GET no longer reaches the audit service"

# The production route loader.
stage
edit $PROD 'i=s.index("create_route '"'"'deny-audit-ingest'"'"'"); j=s.index("}'"'"'", i)+2; s=s[:i]+s[j:]; s=s.replace("\"methods\": [\"GET\"],\n    \"priority\": 10,\n    \"service_id\": \"audit-service-svc\"", "\"methods\": [\"GET\", \"POST\"],\n    \"priority\": 10,\n    \"service_id\": \"audit-service-svc\"", 1)'
expect red "production loader: POST is back on the events route and the deny route is gone"

stage
edit $PROD 's=s.replace("\"methods\": [\"GET\"],\n    \"priority\": 10,\n    \"service_id\": \"audit-service-svc\"", "\"methods\": [\"GET\", \"POST\"],\n    \"priority\": 95,\n    \"service_id\": \"audit-service-svc\"", 1)'
expect red "production loader: the events route takes POST and outranks the deny route"

# The legacy loaders.
stage
edit deployments/docker/load-openidx-routes.sh 'i=s.index("create_route '"'"'deny-audit-ingest'"'"'"); j=s.index("}'"'"'", i)+2; s=s[:i]+s[j:]'
expect red "load-openidx-routes.sh: the deny route is gone"

# The edge seed script, in every DARK_MODE.
stage
edit $SEED 'i=s.index("put openidx-deny-audit-ingest "); j=s.index("\n", i)+1; s=s[:i]+s[j:]'
expect red "edge seed: the deny route is not seeded"

stage
edit $SEED 's=s.replace("\\\"methods\\\":[\\\"POST\\\"],\\\"priority\\\":90", "\\\"methods\\\":[\\\"POST\\\"],\\\"priority\\\":90,\\\"hosts\\\":[\\\"nowhere.invalid\\\"]", 1)'
expect red "edge seed: the deny route only applies to another host"

# nginx (the lite install's edge).
stage
edit $LITE 'import re; s=re.sub(r"    location = /api/v1/audit/events/? \{.*?\n    \}\n", "", s, flags=re.S)'
expect red "lite nginx: the exact-match locations are gone"

stage
edit $LITE 's=s.replace("limit_except GET {", "limit_except GET POST {", 1)'
expect red "lite nginx: limit_except lets POST through"

stage
cat > "$T/deployments/docker/nginx/conf.d/audit-direct.conf" <<'EOF'
server {
    listen 8081;
    location /api/v1/audit/ {
        proxy_pass http://audit-service:8004;
    }
}
EOF
expect red "a new nginx edge proxies the audit prefix with no refusal"

# Helm.
stage
edit $HELM/ingress.yaml 's=s.replace("-audit-service\n                port:\n                  name: edge", "-audit-service\n                port:\n                  name: http", 1)'
expect red "helm: the Ingress sends the audit prefix to the port with ingestion on it"

stage
edit $HELM/audit-service.yaml 's=s.replace("            - name: AUDIT_EDGE_ADDR\n              value: \":8014\"\n", "", 1)'
expect red "helm: the edge port has no listener"

# gateway-service.
stage
edit internal/gateway/routes/audit.go 's=s.replace("router.Any(\"/*path\", refuseEventIngestion, proxyRequest(proxy))", "router.Any(\"/*path\", proxyRequest(proxy))", 1)'
expect red "gateway: the audit proxy forwards everything again"

# Inventory: a new file that names the prefix.
stage
mkdir -p "$T/deployments/traefik"
printf 'http:\n  routers:\n    audit:\n      rule: PathPrefix(`/api/v1/audit`)\n      service: audit\n' > "$T/deployments/traefik/dynamic.yml"
expect red "an unknown edge config that names the audit prefix"

echo "check-audit-ingest-edges self-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
