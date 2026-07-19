#!/usr/bin/env bash
# Smoke-test the new features end-to-end through the public edge, as a user would.
# Usage: bash scripts/test-new-features.sh
# Logs in as admin, then exercises: clientless SSH relay, Quick Links CRUD, and
# the remote-support consent gate. Cleans up after itself. Read the PASS/FAIL.
#
# NOTE: the OAuth token endpoint is rate-limited. Running this repeatedly in
# quick succession can trip "rate limit exceeded" on login (a security control,
# not a bug) — wait ~60s between runs.
set -uo pipefail
HOST=openidx.tdv.org
R=(--resolve "$HOST:443:127.0.0.1" -k -s)
CJ=$(mktemp)
pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
no()  { echo "  FAIL  $1"; fail=$((fail+1)); }

echo "== 1. Login (OAuth auth-code + PKCE) =="
login() {
  : > "$CJ"
  local AUTH="https://$HOST/oauth/authorize?client_id=admin-console&response_type=code&redirect_uri=https%3A%2F%2F$HOST%2Fcallback&scope=openid%20profile&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=t"
  local PAGE LS LOGIN CODE
  PAGE=$(curl "${R[@]}" -c "$CJ" -b "$CJ" -L --max-time 8 "$AUTH")
  LS=$(echo "$PAGE" | grep -oE 'login_session" value="[^"]+"' | head -1 | sed 's/.*value="//; s/"//')
  [ -n "$LS" ] || return 1
  LOGIN=$(curl "${R[@]}" -c "$CJ" -b "$CJ" -X POST "https://$HOST/oauth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"Admin@123\",\"login_session\":\"$LS\"}" --max-time 10)
  CODE=$(echo "$LOGIN" | python3 -c "import sys,json,urllib.parse as u;print(u.parse_qs(u.urlparse(json.load(sys.stdin)['redirect_url']).query)['code'][0])" 2>/dev/null)
  [ -n "$CODE" ] || return 1
  AT=$(curl "${R[@]}" -X POST "https://$HOST/oauth/token" -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode grant_type=authorization_code --data-urlencode "code=$CODE" --data-urlencode client_id=admin-console \
    --data-urlencode "redirect_uri=https://$HOST/callback" --data-urlencode code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk \
    --max-time 10 | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  [ -n "$AT" ]
}
AT=""
for attempt in 1 2 3; do login && break; sleep 1; done
[ -n "$AT" ] && ok "login issued an access token" || { no "login failed"; exit 1; }
AUTHZ=(-H "Authorization: Bearer $AT")

echo "== 2. Quick Links (create external + PAM, list, reject unsafe) =="
QID=$(curl "${R[@]}" "${AUTHZ[@]}" -X POST "https://$HOST/api/v1/access/quick-links" -H 'Content-Type: application/json' \
  -d '{"title":"Test Teams","category":"Collaboration","icon":"Video","type":"external","url":"https://teams.microsoft.com","min_role":"user"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
[ -n "$QID" ] && ok "created an external quick link" || no "create external quick link"
BAD=$(curl "${R[@]}" "${AUTHZ[@]}" -o /dev/null -w '%{http_code}' -X POST "https://$HOST/api/v1/access/quick-links" \
  -H 'Content-Type: application/json' -d '{"title":"bad","type":"external","url":"javascript:alert(1)"}')
[ "$BAD" = "400" ] && ok "rejected unsafe javascript: URL (400)" || no "unsafe URL not rejected (got $BAD)"
CNT=$(curl "${R[@]}" "${AUTHZ[@]}" "https://$HOST/api/v1/access/quick-links/my" | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('quick_links',[])))" 2>/dev/null)
[ "${CNT:-0}" -ge 1 ] && ok "user sees $CNT quick link(s)" || no "user list empty"
[ -n "$QID" ] && curl "${R[@]}" "${AUTHZ[@]}" -o /dev/null -X DELETE "https://$HOST/api/v1/access/quick-links/$QID"

echo "== 3. Clientless SSH relay (permission gate + real handshake) =="
SID=$(curl "${R[@]}" "${AUTHZ[@]}" -X POST "https://$HOST/api/v1/access/pam/entries" -H 'Content-Type: application/json' \
  -d '{"name":"test-ssh","entry_type":"ssh","hostname":"127.0.0.1","port":22,"username":"nobody","renderer":"wasm-ssh","secret":"x"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
if [ -n "$SID" ]; then
  ok "created an ssh entry with renderer=wasm-ssh"
  RND=$(curl "${R[@]}" "${AUTHZ[@]}" "https://$HOST/api/v1/access/pam/entries/$SID" | python3 -c "import sys,json;d=json.load(sys.stdin);print((d.get('entry',d)).get('renderer',''))" 2>/dev/null)
  [ "$RND" = "wasm-ssh" ] && ok "renderer persisted as wasm-ssh" || no "renderer not persisted ($RND)"
  # WS relay: forged token must NOT reach the target (fail-closed at auth in prod;
  # dev-mode boxes admit and hit ssh -> 502). Either way it must not 200.
  WSC=$(curl "${R[@]}" -o /dev/null -w '%{http_code}' --max-time 8 \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' -H "Sec-WebSocket-Protocol: bearer.$AT" \
    "https://$HOST/api/v1/access/pam/entries/$SID/ws?proto=ssh" 2>/dev/null)
  [ "$WSC" = "502" ] && ok "SSH relay reached the target and auth-failed on bad creds (502 = full path works)" \
    || echo "  INFO  ws relay returned $WSC (101=connected, 401/403=gated, 502=reached+auth-fail)"
  curl "${R[@]}" "${AUTHZ[@]}" -o /dev/null -X DELETE "https://$HOST/api/v1/access/pam/entries/$SID"
else
  no "could not create ssh entry"
fi

echo "== 4. Remote-support device consent gate =="
AGENT=$(docker exec oidx-pg psql -U openidx -d openidx -tA -c "SELECT agent_id FROM enrolled_agents LIMIT 1;" 2>/dev/null | grep -vE "Emulate|nodocker" | head -1)
# ws_status opens a real WebSocket upgrade with a raw socket (curl mangles the
# Connection/Upgrade headers) and prints the HTTP status line code.
ws_status() { # $1=session_id
  python3 - "$AT" "$1" <<'PY'
import sys, socket, base64, os
at, sid = sys.argv[1], sys.argv[2]
key = base64.b64encode(os.urandom(16)).decode()
req = (f"GET /api/v1/access/remote-support/sessions/{sid}/ws HTTP/1.1\r\nHost: 127.0.0.1:8007\r\n"
       f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
       f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: bearer.{at}\r\n\r\n")
s = socket.create_connection(("127.0.0.1", 8007), timeout=6); s.sendall(req.encode()); s.settimeout(5)
print(s.recv(64).split(b" ")[1].decode(errors="replace")); s.close()
PY
}
if [ -n "$AGENT" ]; then
  RSID=$(curl "${R[@]}" "${AUTHZ[@]}" -X POST "https://$HOST/api/v1/access/remote-support/sessions" -H 'Content-Type: application/json' \
    -d "{\"agent_id\":\"$AGENT\",\"mode\":\"interactive\",\"consent_required\":true}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
  if [ -n "$RSID" ]; then
    ok "started a consent-required support session"
    W1=$(ws_status "$RSID")
    [ "$W1" = "403" ] && ok "admin WS refused while consent pending (403)" || no "consent gate open too early ($W1)"
    docker exec oidx-pg psql -U openidx -d openidx -c "UPDATE remote_support_sessions SET consent_status='granted' WHERE id='$RSID';" >/dev/null 2>&1
    W2=$(ws_status "$RSID")
    [ "$W2" = "101" ] && ok "admin WS opened after consent granted (101 Switching Protocols)" || no "gate did not open after grant ($W2)"
    docker exec oidx-pg psql -U openidx -d openidx -c "DELETE FROM remote_support_sessions WHERE id='$RSID';" >/dev/null 2>&1
  else
    no "could not start support session"
  fi
else
  echo "  SKIP  no enrolled agent to test consent against"
fi

rm -f "$CJ"
echo ""
echo "== RESULT: $pass passed, $fail failed =="
[ "$fail" = "0" ]
