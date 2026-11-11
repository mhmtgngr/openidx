#!/bin/sh
# OpenIDX agent package postinstall (deb configure / rpm %post).
# Creates the service user, unifies the config dir under /var/lib/openidx-agent
# (copying a legacy /etc/openidx-agent/agent.json once), and enables the
# service and the update timer. Desktop/URL-scheme steps are best-effort.
set -e

CONF=/var/lib/openidx-agent
LEGACY=/etc/openidx-agent

if ! getent group openidx-agent >/dev/null 2>&1; then
	groupadd --system openidx-agent 2>/dev/null || addgroup --system openidx-agent 2>/dev/null || true
fi
if ! getent passwd openidx-agent >/dev/null 2>&1; then
	useradd --system --gid openidx-agent --home-dir "$CONF" --no-create-home \
		--shell /usr/sbin/nologin openidx-agent 2>/dev/null ||
		adduser --system --ingroup openidx-agent --home "$CONF" --no-create-home openidx-agent 2>/dev/null || true
fi

install -d -m 0700 "$CONF"
if [ ! -f "$CONF/agent.json" ] && [ -f "$LEGACY/agent.json" ]; then
	cp -p "$LEGACY"/*.json "$CONF"/ 2>/dev/null || true
	echo "openidx-agent: copied legacy config from $LEGACY to $CONF"
fi
chown -R openidx-agent:openidx-agent "$CONF" 2>/dev/null || true

if command -v update-desktop-database >/dev/null 2>&1; then
	update-desktop-database /usr/share/applications 2>/dev/null || true
fi
if command -v xdg-mime >/dev/null 2>&1; then
	xdg-mime default openidx.desktop x-scheme-handler/openidx 2>/dev/null || true
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	systemctl enable --now openidx-agent-update.timer || true
	systemctl enable openidx-agent.service || true
	# Restart on upgrade, start on fresh install. Without an enrolled
	# agent.json the service waits/retries; that is expected.
	systemctl restart openidx-agent.service || true
fi
exit 0
