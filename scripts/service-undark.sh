#!/usr/bin/env bash
# BREAK-GLASS / undo for the loopback-bind Tier-2 cutover (service-dark-bind.sh
# KEEP=1). Removes the systemd drop-ins and restarts the services back to
# all-interfaces binding. Idempotent.
#
#   bash scripts/service-undark.sh                 # undark the default Tier-2 set
#   UNITS="oidx-audit oidx-admin-api" bash scripts/service-undark.sh
set -uo pipefail
UNITS=${UNITS:-"oidx-audit oidx-governance oidx-provisioning oidx-admin-api"}
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}

for u in $UNITS; do
  d="$HOME/.config/systemd/user/${u}.service.d/10-dark-bind.conf"
  if [ -f "$d" ]; then
    rm -f "$d"; rmdir "$(dirname "$d")" 2>/dev/null || true
    echo "  removed drop-in for $u"
  else
    echo "  ($u had no dark drop-in)"
  fi
done
systemctl --user daemon-reload
for u in $UNITS; do systemctl --user restart "$u" && echo "  restarted $u"; done
sleep 3
echo "== external reachability restored =="
HOSTIP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
declare -A P=( [oidx-audit]=8004 [oidx-governance]=8002 [oidx-provisioning]=8003 [oidx-admin-api]=8005 )
for u in $UNITS; do
  p=${P[$u]:-}; [ -n "$p" ] || continue
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://$HOSTIP:$p/health/live" 2>/dev/null)
  echo "  $u http://$HOSTIP:$p -> ${c:-refused}"
done
