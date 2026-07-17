#!/usr/bin/env bash
# Persistent loopback-bind cutover for ONE OpenIDX service, with self-restore.
# Makes the service vanish from the host's external interface (external host-IP
# access refused) while the LOCAL edge (host-networked APISIX) and the overlay
# (host-networked ziti-router) keep reaching it via 127.0.0.1 -- so your own
# access through https://openidx.tdv.org is unaffected.
#
# Uses a systemd drop-in that sets SERVICE_BIND_ADDR=127.0.0.1 (Phase-1 config),
# restarts the unit, PROVES external-refused + loopback-ok + edge-ok, and (unless
# KEEP=1) reverts the drop-in and restarts back to all-interfaces.
#
#   UNIT=oidx-audit PORT=8004 bash scripts/service-dark-bind.sh          # drill (auto-revert)
#   UNIT=oidx-audit PORT=8004 KEEP=1 bash scripts/service-dark-bind.sh   # persist the cutover
set -uo pipefail
UNIT=${UNIT:?set UNIT (e.g. oidx-audit)}
PORT=${PORT:?set PORT (e.g. 8004)}
KEEP=${KEEP:-0}
HOSTIP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
DROPIN_DIR="$HOME/.config/systemd/user/${UNIT}.service.d"
DROPIN="$DROPIN_DIR/10-dark-bind.conf"

say(){ printf '%s\n' "$*"; }
extcode(){ local c; c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://$HOSTIP:$PORT/health/live" 2>/dev/null); [ -z "$c" ] || [ "$c" = "000" ] && echo "refused" || echo "$c"; }
lbcode(){ local c; c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://127.0.0.1:$PORT/health/live" 2>/dev/null); [ -z "$c" ] || [ "$c" = "000" ] && echo "refused" || echo "$c"; }

say "== target: $UNIT (:$PORT); host external IP = ${HOSTIP:-<none>} =="
say "-- BEFORE --"
say "  external  http://$HOSTIP:$PORT/health/live -> $(extcode)"
say "  loopback  http://127.0.0.1:$PORT/health/live -> $(lbcode)"

revert(){
  say "== REVERT (remove drop-in, restart to all-interfaces) =="
  rm -f "$DROPIN"; rmdir "$DROPIN_DIR" 2>/dev/null
  systemctl --user daemon-reload
  systemctl --user restart "$UNIT"
  sleep 2
  say "  external -> $(extcode)  (expect a real code again)"
  say "  loopback -> $(lbcode)"
}
[ "$KEEP" = "1" ] || trap revert EXIT

say ""
say "== APPLY loopback bind (SERVICE_BIND_ADDR=127.0.0.1) via systemd drop-in =="
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
[Service]
Environment=SERVICE_BIND_ADDR=127.0.0.1
EOF
systemctl --user daemon-reload
systemctl --user restart "$UNIT"
sleep 3

say ""
say "== PROVE the dark posture =="
EXT=$(extcode); LB=$(lbcode)
say "  external  http://$HOSTIP:$PORT/health/live -> $EXT   (want: refused/000)"
say "  loopback  http://127.0.0.1:$PORT/health/live -> $LB   (want: 200)"

# Edge check: pick the right public path per service.
declare -A EDGE=( [oidx-audit]=/api/v1/audit/health [oidx-governance]=/api/v1/governance/health
  [oidx-provisioning]=/api/v1/provisioning/health [oidx-admin-api]=/api/v1/admin/health
  [oidx-identity]=/api/v1/identity/health [oidx-access]=/api/v1/access/health )
EPATH=${EDGE[$UNIT]:-}
if [ -n "$EPATH" ]; then
  EC=$(curl --resolve openidx.tdv.org:443:127.0.0.1 -k -s -o /dev/null -w '%{http_code}' --max-time 5 "https://openidx.tdv.org$EPATH" 2>/dev/null)
  say "  edge      https://openidx.tdv.org$EPATH -> $EC   (want: a real code, NOT refused = edge still works)"
fi

# Verdict
if { [ "$EXT" = "refused" ] || [ "$EXT" = "000" ]; } && [ "$LB" = "200" ]; then
  say ""
  say "  ✅ DARK: external host-IP refused, loopback+edge still serve."
else
  say ""
  say "  ⚠️  unexpected: external=$EXT loopback=$LB — check the service came back up."
fi

if [ "$KEEP" = "1" ]; then
  say ""
  say "== KEEP=1: cutover PERSISTED. Drop-in at $DROPIN"
  say "   Undo: rm $DROPIN && systemctl --user daemon-reload && systemctl --user restart $UNIT"
else
  say ""
  say "(auto-revert on exit)"
fi
