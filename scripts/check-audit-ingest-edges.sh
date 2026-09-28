#!/usr/bin/env bash
# Guard: no shipped edge forwards audit event ingestion from outside.
#
# WHY: POST /api/v1/audit/events writes an event into an organization's audit
# trail -- actor, client address, action, outcome and details as the body
# states them, under the organization X-Org-Slug names -- and the sealer chains
# it like any other event. It is meant for OpenIDX's own services only. The
# audit service now demands the internal service token on it, and the edges
# refuse it as well: every reference edge used to forward the whole
# /api/v1/audit prefix, so a service-to-service route was one request away
# from anyone who could reach the console. The console reads the same path
# with GET, which is why "route less of the prefix" is not the fix and why the
# shape is easy to lose again: a route that re-adds POST, a deny route whose
# priority drops below the route it shadows, a new edge config that forwards
# the prefix. None of those fails a YAML parse or a smoke test. So:
#
#   APISIX (the compose standalone file, the three route loaders and the edge
#     seed script, in every DARK_MODE): for POST /api/v1/audit/events and its
#     trailing-slash form, the route APISIX would pick -- exact paths before
#     prefixes, then the longest prefix, then priority; methods and hosts
#     honoured -- must not forward to the audit service. The console's GET must
#     still reach it.
#   nginx (every .conf under deployments/ that proxies to the audit service):
#     the location nginx would pick for the same two paths must refuse POST
#     (limit_except GET { deny all; }) or not proxy to the audit service; GET
#     must still reach it.
#   Helm: the API Ingress sends every audit path to the audit service's edge
#     port, the listener with no ingestion on it (AUDIT_EDGE_ADDR); an Ingress
#     cannot match on method. The Deployment must open that port and the
#     Service must name it.
#   gateway-service: its audit proxy refuses the route before forwarding.
#   Anything else under deployments/ that names /api/v1/audit must be listed
#     below, checked or with a reason, so a new edge cannot appear unnoticed.
#
# Usage: check-audit-ingest-edges.sh [--enforce]
#   --enforce  exit non-zero on a finding (the CI mode)
#   default    print findings and exit 0
# OPENIDX_EDGE_ROOT overrides the repository root (the .test.sh uses it).
set -uo pipefail

ROOT="${OPENIDX_EDGE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENFORCE=0
[ "${1:-}" = "--enforce" ] && ENFORCE=1

if [ ! -d "$ROOT/deployments" ]; then
  echo "check-audit-ingest-edges: no deployments/ under $ROOT" >&2
  exit 2
fi

# The edge seed script, run for real in each DARK_MODE with a put() that
# prints each route's JSON instead of sending it: its conditionals decide
# which routes exist, so they are executed rather than read.
SEED="$ROOT/deployments/apisix-edge/seed-edge-routes.sh"
SEEDED=""
if [ -f "$SEED" ]; then
  for mode in off tier2 tier1; do
    out="$(sed -e 's/^put() {.*$/put() { printf "ROUTE\\t%s\\t%s\\n" "$1" "$2"; }/' \
               -e 's/^put_global() {.*$/put_global() { :; }/' "$SEED" |
           DARK_MODE="$mode" DRY_RUN=1 bash 2>/dev/null)" || {
      echo "check-audit-ingest-edges: seed-edge-routes.sh failed in DARK_MODE=$mode" >&2
      exit 2
    }
    SEEDED+="$(printf '%s\n' "$out" | sed "s/^ROUTE\\t/ROUTE\\t$mode\\t/")"$'\n'
  done
fi

ROOT="$ROOT" ENFORCE="$ENFORCE" SEEDED="$SEEDED" python3 - <<'PYEOF'
import json, os, re, sys

root = os.environ["ROOT"]
enforce = os.environ["ENFORCE"] == "1"
findings = []
def finding(msg): findings.append(msg)

INGEST = ["/api/v1/audit/events", "/api/v1/audit/events/"]
AUDIT_UPSTREAMS = ("audit-service:8004", "127.0.0.1:8004", "localhost:8004")

def rel(p): return os.path.relpath(p, root)

# ---------------------------------------------------------------- APISIX ----
def is_deny(r):
    fi = ((r.get("plugins") or {}).get("fault-injection") or {}).get("abort") or {}
    return fi.get("http_status") in (403, 404, 405)

def uris(r):
    u = r.get("uris") or []
    if r.get("uri"):
        u = u + [r["uri"]]
    return u

def hosts(r):
    h = r.get("hosts") or []
    if r.get("host"):
        h = h + [r["host"]]
    return h

def method_ok(r, m):
    ms = r.get("methods")
    return not ms or m in ms

def host_ok(r, h):
    hs = hosts(r)
    return not hs or h in hs

def pick(routes, path, method, host):
    """The route APISIX's radixtree router would choose."""
    live = [r for r in routes if method_ok(r, method) and host_ok(r, host)]
    exact = [r for r in live if path in uris(r)]
    if exact:
        return max(exact, key=lambda r: r.get("priority", 0))
    best, key = None, None
    for r in live:
        for u in uris(r):
            if u.endswith("*") and path.startswith(u[:-1]):
                k = (len(u) - 1, r.get("priority", 0))
                if key is None or k > key:
                    best, key = r, k
    return best

def forwards_to_audit(r, services, upstreams):
    if r is None or is_deny(r):
        return False
    nodes = dict(((r.get("upstream") or {}).get("nodes") or {}))
    up = r.get("upstream_id")
    svc = services.get(r.get("service_id") or "")
    if svc:
        nodes.update(((svc.get("upstream") or {}).get("nodes") or {}))
        up = up or svc.get("upstream_id")
    if up and up in upstreams:
        nodes.update((upstreams[up].get("nodes") or {}))
    return any(any(a in n for a in AUDIT_UPSTREAMS) for n in nodes)

def check_apisix(name, routes, services=None, upstreams=None):
    services, upstreams = services or {}, upstreams or {}
    contexts = {None}
    for r in routes:
        contexts.update(hosts(r))
    serves_audit = False
    for host in contexts:
        for path in INGEST:
            chosen = pick(routes, path, "POST", host)
            if forwards_to_audit(chosen, services, upstreams):
                finding(f"{name}: POST {path}" + (f" (host {host})" if host else "") +
                        f" is forwarded to the audit service by route {chosen.get('name') or chosen.get('id')!r}; "
                        "refuse it at the edge (a fault-injection route for POST that outranks it)")
        if forwards_to_audit(pick(routes, INGEST[0], "GET", host), services, upstreams):
            serves_audit = True
    return serves_audit

# The compose standalone file.
p = os.path.join(root, "deployments/docker/apisix/apisix.yaml")
if os.path.exists(p):
    import yaml
    doc = yaml.safe_load(open(p).read().replace("#END", "")) or {}
    if not check_apisix(rel(p), doc.get("routes") or []):
        finding(f"{rel(p)}: GET /api/v1/audit/events no longer reaches the audit service; the console reads the trail there")
else:
    finding("deployments/docker/apisix/apisix.yaml is missing")

# The Admin API route loaders: create_route/create_service/create_upstream
# '<id>' '<json>'.
CALL = re.compile(r"create_(route|service|upstream)\s+'([^']+)'\s+'(\{.*?\n\})'", re.S)
for loader in ("load-production-routes.sh", "load-openidx-routes.sh", "load-apisix-routes.sh"):
    p = os.path.join(root, "deployments/docker", loader)
    if not os.path.exists(p):
        continue
    routes, services, upstreams = [], {}, {}
    for kind, ident, body in CALL.findall(open(p).read()):
        try:
            obj = json.loads(body)
        except ValueError as e:
            finding(f"{rel(p)}: {kind} {ident} is not valid JSON ({e})")
            continue
        obj.setdefault("id", ident)
        {"route": lambda: routes.append(obj),
         "service": lambda: services.__setitem__(ident, obj),
         "upstream": lambda: upstreams.__setitem__(ident, obj)}[kind]()
    if not routes:
        finding(f"{rel(p)}: no routes found; the loader's shape changed and this guard no longer reads it")
        continue
    if not check_apisix(rel(p), routes, services, upstreams):
        finding(f"{rel(p)}: GET /api/v1/audit/events no longer reaches the audit service")

# The edge seed script, as executed above.
seeded = {}
for line in os.environ.get("SEEDED", "").splitlines():
    parts = line.split("\t", 3)
    if len(parts) == 4 and parts[0] == "ROUTE":
        try:
            seeded.setdefault(parts[1], []).append(dict(json.loads(parts[3]), name=parts[2]))
        except ValueError as e:
            finding(f"deployments/apisix-edge/seed-edge-routes.sh: route {parts[2]} ({parts[1]}) is not valid JSON ({e})")
if os.path.exists(os.path.join(root, "deployments/apisix-edge/seed-edge-routes.sh")):
    for mode in ("off", "tier2", "tier1"):
        routes = seeded.get(mode) or []
        if not routes:
            finding(f"deployments/apisix-edge/seed-edge-routes.sh: DARK_MODE={mode} seeded no routes")
            continue
        serves = check_apisix(f"deployments/apisix-edge/seed-edge-routes.sh (DARK_MODE={mode})", routes)
        if mode == "off" and not serves:
            finding("deployments/apisix-edge/seed-edge-routes.sh: GET /api/v1/audit/events no longer reaches the audit service")

# ----------------------------------------------------------------- nginx ----
def blocks(text, start):
    """The body of the brace block opening at or after start."""
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1:j], j + 1
    return text[i + 1:], len(text)

LOC = re.compile(r"^\s*location\s+(=|\^~|~\*|~)?\s*(\S+)\s*\{", re.M)
def locations(server):
    out, pos = [], 0
    while True:
        m = LOC.search(server, pos)
        if not m:
            return out
        body, end = blocks(server, m.start())
        out.append((m.group(1) or "", m.group(2), body))
        pos = end

def proxies_to_audit(body):
    return any(a in body for a in AUDIT_UPSTREAMS) and "proxy_pass" in body

LIMIT = re.compile(r"limit_except\s+([A-Z ]+)\{\s*deny\s+all;\s*\}")
def refuses(body, method):
    m = LIMIT.search(body)
    return bool(m) and method not in m.group(1).split()

def select(locs, path):
    for mod, loc, body in locs:
        if mod == "=" and loc == path:
            return (mod, loc, body)
    prefixes = [l for l in locs if l[0] in ("", "^~") and path.startswith(l[1])]
    longest = max(prefixes, key=lambda l: len(l[1])) if prefixes else None
    if longest and longest[0] == "^~":
        return longest
    for mod, loc, body in locs:
        if mod in ("~", "~*") and re.search(loc, path, re.I if mod == "~*" else 0):
            return (mod, loc, body)
    return longest

for dirpath, _, files in os.walk(os.path.join(root, "deployments")):
    for f in files:
        if not f.endswith(".conf"):
            continue
        p = os.path.join(dirpath, f)
        text = open(p, errors="replace").read()
        for sm in re.finditer(r"^\s*server\s*\{", text, re.M):
            server, _ = blocks(text, sm.start())
            locs = locations(server)
            if not any(proxies_to_audit(b) for _, _, b in locs):
                continue
            for path in INGEST:
                chosen = select(locs, path)
                if chosen and proxies_to_audit(chosen[2]) and not refuses(chosen[2], "POST"):
                    finding(f"{rel(p)}: POST {path} is proxied to the audit service by location "
                            f"{(chosen[0] + ' ' + chosen[1]).strip()}; add an exact-match location that "
                            "refuses it (limit_except GET { deny all; })")
            chosen = select(locs, INGEST[0])
            if not (chosen and proxies_to_audit(chosen[2]) and not refuses(chosen[2], "GET")):
                finding(f"{rel(p)}: GET /api/v1/audit/events no longer reaches the audit service")

# ------------------------------------------------------------------ Helm ----
chart = os.path.join(root, "deployments/kubernetes/helm/openidx/templates")
if os.path.isdir(chart):
    ing = open(os.path.join(chart, "ingress.yaml")).read()
    seen = 0
    for m in re.finditer(r"name:\s*\{\{\s*include \"openidx.fullname\" \$ \}\}-audit-service\s*\n\s*port:\s*\n\s*name:\s*(\S+)", ing):
        seen += 1
        if m.group(1) != "edge":
            finding(f"{rel(os.path.join(chart, 'ingress.yaml'))}: an Ingress path sends the audit prefix to port "
                    f"{m.group(1)!r}; it must be the edge port, the listener with no event ingestion on it")
    if seen == 0:
        finding(f"{rel(os.path.join(chart, 'ingress.yaml'))}: no audit-service backend found; the template's shape changed and this guard no longer reads it")
    dep = open(os.path.join(chart, "audit-service.yaml")).read()
    if not re.search(r"-\s*name:\s*edge\s*\n\s*containerPort:\s*8014", dep):
        finding("helm audit-service.yaml: the Deployment does not open the edge port (containerPort 8014, name edge)")
    if not re.search(r"name:\s*AUDIT_EDGE_ADDR\s*\n\s*value:\s*\":8014\"", dep):
        finding("helm audit-service.yaml: AUDIT_EDGE_ADDR is not \":8014\"; the edge port would have no listener")
    if not re.search(r"targetPort:\s*edge\s*\n\s*protocol:\s*TCP\s*\n\s*name:\s*edge", dep):
        finding("helm audit-service.yaml: the Service does not name the edge port")

# ------------------------------------------------------------- gateway ----
gw = os.path.join(root, "internal/gateway/routes/audit.go")
if os.path.exists(gw):
    if not re.search(r'router\.Any\("/\*path",\s*refuseEventIngestion,', open(gw).read()):
        finding("internal/gateway/routes/audit.go: the audit proxy no longer refuses event ingestion before forwarding")

# ------------------------------------------------------------- inventory ----
# Every file under deployments/ that names the audit prefix, and what it is.
CHECKED = {
    "deployments/docker/apisix/apisix.yaml",
    "deployments/docker/load-production-routes.sh",
    "deployments/docker/load-openidx-routes.sh",
    "deployments/docker/load-apisix-routes.sh",
    "deployments/apisix-edge/seed-edge-routes.sh",
    "deployments/docker/nginx/admin-console.lite.conf",
    "deployments/kubernetes/helm/openidx/templates/ingress.yaml",
    "deployments/kubernetes/helm/openidx/templates/audit-service.yaml",
}
NOT_AN_EDGE = {
    # Tests and the seed script's own self-test.
    "deployments/apisix-edge/seed-edge-routes.test.sh": "self-test of the seed script",
    "deployments/docker/routes_test.go": "Go test of the production loader",
    "deployments/docker/apisix_test.go": "Go test of the standalone APISIX file",
    "deployments/docker/config_test.go": "Go test of the compose files",
    # Named, not routed.
    "deployments/docker/apisix/audit_route.yaml": "reference file no deployment loads; its /events route is GET-only",
    "deployments/docker/nginx/conf.d/openidx.tdv.org.conf": "comments only; /api/v1/ goes to APISIX, which refuses the POST",
    "deployments/terraform/modules/edge-common/rules.json": "a CDN rate-limit rule for /api/v1/audit/events/search; the origin edge refuses the POST",
    "deployments/docker/docker-compose.yml": "comments only",
    "deployments/docker/docker-compose.lite.yml": "comments only",
    "deployments/kubernetes/helm/openidx/values.yaml": "comments only",
    "deployments/docker/opa/policies/authz.rego": "an authorization policy's comment; OPA routes nothing",
    "deployments/kubernetes/helm/openidx/files/opa/authz.rego": "an authorization policy's comment; OPA routes nothing",
}
for dirpath, _, files in os.walk(os.path.join(root, "deployments")):
    for f in files:
        p = os.path.join(dirpath, f)
        r = rel(p)
        if f.endswith(".md") or r in CHECKED or r in NOT_AN_EDGE:
            continue
        try:
            text = open(p, errors="replace").read()
        except OSError:
            continue
        if "/api/v1/audit" in text:
            finding(f"{r} names /api/v1/audit and this guard does not know it: if it routes the prefix, "
                    "add it to the checks above; if it does not, list it in NOT_AN_EDGE with the reason")

if findings:
    for f in findings:
        print("check-audit-ingest-edges: " + f, file=sys.stderr)
    sys.exit(1 if enforce else 0)
print("check-audit-ingest-edges: ok — no shipped edge forwards POST /api/v1/audit/events, and GET still reaches the audit service")
PYEOF
