#!/bin/sh
# Stop and disable on removal only, not on upgrade (deb: $1=upgrade, rpm: $1=1).
set -e
case "${1:-}" in
upgrade | 1) exit 0 ;;
esac
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl disable --now openidx-agent-update.timer 2>/dev/null || true
	systemctl disable --now openidx-agent.service 2>/dev/null || true
	systemctl disable --now openidx-tunnel.service 2>/dev/null || true
fi
exit 0
