#!/usr/bin/env bash
# box-pam-units.sh — user systemd units for the PAM OpenZiti broker containers.
#
# On the reference box the three Ziti-broker containers created by
# deployments/docker/deploy-pam-ziti-broker.sh (pam-guacd-ziti,
# pam-ziti-tunnel, pam-guacamole-ziti) have no unit, and rootless
# `--restart unless-stopped` does nothing at boot while the user
# podman-restart.service is disabled. After every reboot they stay stopped
# and reach_mode=ziti PAM sessions fail until someone starts them by hand.
#
# This writes one unit per container into ~/.config/systemd/user and enables
# it (enable only: starting a unit over an already-running container is left
# to the next boot, as docs/architecture/reboot-safety.md advises).
#
# Why hand-written units and not `podman generate systemd`:
#   - `--new` recreates the container from its create command on every start,
#     and that command is copied into the unit file verbatim. The guacamole
#     container is created with POSTGRESQL_PASSWORD in its environment, so the
#     unit would hold a database password in a world-readable file.
#   - without `--new` podman 4.x emits Type=forking with a PIDFile under
#     overlay-containers/<container-id>/, which goes stale the next time the
#     container is recreated (scripts/check-systemd-container-units.sh exists
#     because of that). These units are already in the form that check asks
#     for: Type=simple, no PIDFile, `podman start --attach <name>`.
#   - Quadlet would need the containers' full definition, secrets included,
#     in a .container file — same problem as `--new`.
# The units therefore reuse the existing containers with their exact config.
#
# Ordering: pam-guacd-ziti owns the shared network namespace; the tunnel and
# the guacamole webapp join it (`--network container:pam-guacd-ziti`), so they
# are bound to it and restart with it. The webapp also needs pam-guac-db,
# which oidx-pam-broker.service starts.
#
# Usage:
#   scripts/box-pam-units.sh            # dry run: show what would change
#   scripts/box-pam-units.sh --apply    # write changed units, daemon-reload, enable
#
# Idempotent: an unchanged unit is not rewritten, and enabling an enabled unit
# is a no-op.
set -euo pipefail

UNIT_DIR="${UNIT_DIR:-$HOME/.config/systemd/user}"
PODMAN="${PODMAN:-/usr/bin/podman}"
APPLY=0

case "${1:-}" in
  "") ;;
  --dry-run) ;;
  --apply) APPLY=1 ;;
  -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
  *) echo "usage: $0 [--dry-run|--apply]" >&2; exit 2 ;;
esac

# unit_for <container> <extra [Unit] lines>
unit_for() {
  local name=$1 deps=$2
  cat <<EOF
# container-${name}.service — written by scripts/box-pam-units.sh; edit there.
[Unit]
Description=OpenIDX PAM broker container ${name}
Wants=network-online.target
After=network-online.target
RequiresMountsFor=%t/containers
${deps:+${deps}
}
[Service]
Environment=PODMAN_SYSTEMD_UNIT=%n
Type=simple
Restart=always
RestartSec=5s
TimeoutStopSec=70
ExecStart=${PODMAN} start --attach ${name}
ExecStop=${PODMAN} stop -t 10 ${name}

[Install]
WantedBy=default.target
EOF
}

NETNS_OWNER=pam-guacd-ziti
bound="BindsTo=container-${NETNS_OWNER}.service
After=container-${NETNS_OWNER}.service"

declare -A DEPS=(
  [pam-guacd-ziti]=""
  [pam-ziti-tunnel]="$bound"
  [pam-guacamole-ziti]="$bound
Wants=oidx-pam-broker.service
After=oidx-pam-broker.service"
)
ORDER=(pam-guacd-ziti pam-ziti-tunnel pam-guacamole-ziti)

[ "$APPLY" = 1 ] || echo "DRY RUN (pass --apply to write and enable). Unit dir: $UNIT_DIR"
[ "$APPLY" = 0 ] || mkdir -p "$UNIT_DIR"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
changed=0
units=()
for name in "${ORDER[@]}"; do
  unit="container-${name}.service"
  units+=("$unit")
  unit_for "$name" "${DEPS[$name]}" > "$tmp/$unit"
  dest="$UNIT_DIR/$unit"
  if [ -f "$dest" ] && cmp -s "$tmp/$unit" "$dest"; then
    echo "unchanged  $unit"
    continue
  fi
  changed=1
  if [ -f "$dest" ]; then
    echo "update     $unit"
    diff -u "$dest" "$tmp/$unit" || true
  else
    echo "create     $unit"
    [ "$APPLY" = 1 ] || cat "$tmp/$unit"
  fi
  if [ "$APPLY" = 1 ]; then
    install -m 644 "$tmp/$unit" "$dest"
  fi
done

if [ "$APPLY" = 0 ]; then
  echo
  echo "would run: systemctl --user daemon-reload   (only if a unit changed: $changed)"
  echo "would run: systemctl --user enable ${units[*]}"
  echo "would check: loginctl show-user \"\$USER\" -p Linger   (must be Linger=yes)"
  exit 0
fi

[ "$changed" = 0 ] || systemctl --user daemon-reload
systemctl --user enable "${units[@]}"
for u in "${units[@]}"; do
  printf '%-40s %s\n' "$u" "$(systemctl --user is-enabled "$u" 2>/dev/null || true)"
done
linger=$(loginctl show-user "$USER" -p Linger 2>/dev/null || true)
echo "$linger"
[ "$linger" = "Linger=yes" ] || echo "WARNING: lingering is off; user units do not start at boot without it (loginctl enable-linger \"\$USER\")."
echo "Units take over at the next boot. Verify after a reboot: systemctl --user --failed"
