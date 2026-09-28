#!/usr/bin/env bash
# Mutation test for the console-csp guard. Each fixture is a way the console's
# policy has been, or could be, lost or loosened; the guard must flag those,
# leave alone the locations that are not the console, and notice when it is
# watching nothing at all.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0; ok(){ echo "  OK  $1"; }; bad(){ echo "  FAIL  $1"; fails=$((fails+1)); }
tmps=()
fixture(){ local d; d=$(mktemp -d); tmps+=("$d"); mkdir -p "$d/deployments/docker/nginx"; echo "$d"; }
run(){ CONSOLE_CSP_ROOT="$1" bash scripts/check-console-csp.sh; }
enforce(){ CONSOLE_CSP_ROOT="$1" bash scripts/check-console-csp.sh --enforce >/dev/null 2>&1; }

GOOD="default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src * data: blob:; connect-src * ws: wss:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

# conf <static-asset headers> <index.html headers> <location / headers>
conf(){ cat <<EOF
server {
    listen 8080;
    root /usr/share/nginx/html;
    add_header X-Content-Type-Options "nosniff" always;
    location ~* \.(js|css|png|svg)$ {
        expires 1y;
$1
    }
    location /api/ { proxy_pass http://apisix:9080; }
    location ^~ /saml/ { set \$upstream http://oauth-service:8006; proxy_pass \$upstream; }
    location = /health { return 200 "healthy\n"; }
    location = /index.html {
$2
    }
    location / {
$3
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
}
csp(){ echo "        add_header Content-Security-Policy \"$1\" always;"; }

# The shipped shape: the policy on each console location, none on the API,
# SAML and health locations.
good=$(fixture); conf "$(csp "$GOOD")" "$(csp "$GOOD")" "$(csp "$GOOD")" > "$good/deployments/docker/nginx/console.conf"
out=$(run "$good")
echo "$out" | grep -q 'offender:' && bad "flagged a console config that sends the policy: $out" || ok "passes a config that sends the policy on every console location"
echo "$out" | grep -q '1 config(s) serve the console, 3 location(s) checked, 0 offender(s)' && ok "checks the three console locations and not the API, SAML or health ones" || bad "wrong counts: $out"
enforce "$good" && ok "enforce passes a good config" || bad "enforce failed a good config"

# The v1.38.0 shape: no policy anywhere.
none=$(fixture); conf "        add_header Cache-Control \"public, immutable\";" "" "" > "$none/deployments/docker/nginx/console.conf"
out=$(run "$none")
[ "$(echo "$out" | grep -c 'sends no Content-Security-Policy')" = 3 ] && ok "flags every console location of a config with no policy" || bad "missed a location without a policy: $out"
enforce "$none" && bad "enforce passed a config with no policy" || ok "enforce fails a config with no policy"

# The trap this guard exists for: a policy set once for the server, and a
# location that adds Cache-Control and so silently drops it.
dropped=$(fixture)
conf "        add_header Cache-Control \"public, immutable\";" "" "" | sed "s|^    add_header X-Content-Type-Options \"nosniff\" always;|    add_header Content-Security-Policy \"$GOOD\" always;|" > "$dropped/deployments/docker/nginx/console.conf"
out=$(run "$dropped")
echo "$out" | grep -q 'location ~\* .*sends no Content-Security-Policy' && ok "flags a location whose own add_header drops the server's policy" || bad "missed the dropped policy: $out"
echo "$out" | grep -q 'location /:' && bad "flagged a location that inherits the server's policy" || ok "accepts a location that inherits the server's policy"

# Loosened policies, one weakness each.
for case in \
  "unsafe-inline|${GOOD/script-src \'self\'/script-src \'self\' \'unsafe-inline\'}|script-src also allows 'unsafe-inline'" \
  "unsafe-eval|${GOOD/script-src \'self\'/script-src \'self\' \'unsafe-eval\'}|script-src also allows 'unsafe-eval'" \
  "another script host|${GOOD/script-src \'self\'/script-src \'self\' https://cdn.example.com}|script-src also allows https://cdn.example.com" \
  "a scheme source|${GOOD/script-src \'self\'/script-src \'self\' https:}|script-src also allows https:" \
  "no script-src|${GOOD/script-src \'self\' https:\/\/challenges.cloudflare.com; /}|no script-src" \
  "no object-src|${GOOD/object-src \'none\'; /}|object-src is not 'none'" \
  "an open base-uri|${GOOD/base-uri \'self\'/base-uri *}|base-uri is not" \
  "no form-action|${GOOD/form-action \'self\'; /}|form-action is not" \
  "framing by anyone|${GOOD/frame-ancestors \'none\'/frame-ancestors *}|frame-ancestors is not"; do
  name=${case%%|*}; rest=${case#*|}; policy=${rest%|*}; want=${rest##*|}
  d=$(fixture); conf "$(csp "$GOOD")" "$(csp "$policy")" "$(csp "$GOOD")" > "$d/deployments/docker/nginx/console.conf"
  out=$(run "$d")
  echo "$out" | grep -F -q "location = /index.html: " && echo "$out" | grep -F -q "$want" && ok "flags $name" || bad "missed $name: $out"
done

# A policy sent without `always` is left off the 404s the SPA fallback answers.
noalways=$(fixture); conf "$(csp "$GOOD")" "        add_header Content-Security-Policy \"$GOOD\";" "$(csp "$GOOD")" > "$noalways/deployments/docker/nginx/console.conf"
run "$noalways" | grep -q 'not sent `always`' && ok "flags a policy not sent always" || bad "missed a policy not sent always"

# A front proxy that serves the console by proxying to it: its console
# locations are held to the policy, and its other locations are not.
front=$(fixture); cat > "$front/deployments/docker/nginx/edge.conf" <<EOF
server {
    listen 443 ssl;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'" always;
    location / {
        proxy_pass http://admin_console;
        location ~* \.(js|css)$ {
            proxy_pass http://admin_console;
            add_header Cache-Control "public, immutable";
            add_header Content-Security-Policy "$GOOD" always;
        }
    }
    location /access/ { proxy_pass http://access_service; }
}
EOF
out=$(run "$front")
echo "$out" | grep -q "edge.conf: location /: script-src also allows 'unsafe-inline'" && ok "flags a proxy to the console that sends it the server's loose policy" || bad "missed the front proxy's loose policy: $out"
echo "$out" | grep -q 'location ~\*' && bad "flagged the front proxy's nested location that sends the policy" || ok "accepts the nested proxy location that sends the policy"
echo "$out" | grep -q '/access/' && bad "flagged a location that proxies to another service" || ok "leaves locations proxied elsewhere alone"

# Configs that are not the console: an API-only edge, and the demo app.
other=$(fixture); conf "$(csp "$GOOD")" "$(csp "$GOOD")" "$(csp "$GOOD")" > "$other/deployments/docker/nginx/console.conf"
cat > "$other/deployments/docker/nginx/api.conf" <<'EOF'
server { listen 9000; location / { proxy_pass http://apisix:9080; } }
EOF
mkdir -p "$other/cmd/simple-web"; conf "" "" "" > "$other/cmd/simple-web/nginx.conf"
out=$(run "$other")
echo "$out" | grep -q 'api.conf\|simple-web' && bad "flagged a config that does not serve the console: $out" || ok "ignores an API edge and the listed demo app"

# The wiring: what the image copies in, and what compose mounts over it, must
# be files the guard checked.
wiring=$(fixture); conf "$(csp "$GOOD")" "$(csp "$GOOD")" "$(csp "$GOOD")" > "$wiring/deployments/docker/nginx/console.conf"
cat > "$wiring/deployments/docker/nginx/other.conf" <<'EOF'
server { listen 8080; location / { return 200; } }
EOF
cat > "$wiring/deployments/docker/Dockerfile.admin-console" <<'EOF'
FROM nginx:alpine AS production
COPY --from=builder /app/dist /usr/share/nginx/html
COPY deployments/docker/nginx/other.conf /etc/nginx/conf.d/default.conf
EOF
cat > "$wiring/deployments/docker/docker-compose.lite.yml" <<'EOF'
services:
  admin-console:
    volumes:
      - ./nginx/other.conf:/etc/nginx/conf.d/default.conf:ro
EOF
out=$(run "$wiring")
echo "$out" | grep -q 'Dockerfile.admin-console installs deployments/docker/nginx/other.conf' && ok "flags an image that copies in a config the guard does not see serving the console" || bad "missed the image wiring: $out"
echo "$out" | grep -q 'docker-compose.lite.yml installs deployments/docker/nginx/other.conf' && ok "flags a compose mount of such a config" || bad "missed the compose wiring: $out"
sed -i 's#other.conf#console.conf#' "$wiring/deployments/docker/Dockerfile.admin-console" "$wiring/deployments/docker/docker-compose.lite.yml"
run "$wiring" | grep -q 'installs' && bad "flagged wiring to the checked config" || ok "accepts wiring to the checked config"

# The guard must not pass by matching nothing.
empty=$(fixture)
out=$(run "$empty")
echo "$out" | grep -q 'checking nothing' && ok "says so when it finds no console config" || bad "stayed quiet over an empty tree"
enforce "$empty" && bad "enforce passed over an empty tree" || ok "enforce fails over an empty tree"

rm -rf "${tmps[@]}"
[ "$fails" -eq 0 ] && echo "check-console-csp PASS" || { echo "FAIL ($fails)"; exit 1; }
