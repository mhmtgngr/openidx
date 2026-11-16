#!/usr/bin/env bash
# OpenIDX connector installer: enrolls and runs an OpenZiti edge router in a
# container on this host. Without --advertised the connector is outbound-only
# (it dials the controller and other routers; nothing listens on this host),
# which is the common on-prem "private site" case behind NAT.
#
# Usage:
#   connector-install.sh --token <JWT> --ctrl <host:port> --name <name> \
#     [--advertised <addr>] [--image-tag <tag>] [--uninstall]
#
# DRYRUN=1 prints the container command instead of running it (for tests).
set -euo pipefail

TOKEN=""
CTRL=""
NAME=""
ADVERTISED=""
IMAGE_TAG="1.6.12"
UNINSTALL=0

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --token)      TOKEN="${2:-}"; shift 2 ;;
    --ctrl)       CTRL="${2:-}"; shift 2 ;;
    --name)       NAME="${2:-}"; shift 2 ;;
    --advertised) ADVERTISED="${2:-}"; shift 2 ;;
    --image-tag)  IMAGE_TAG="${2:-}"; shift 2 ;;
    --uninstall)  UNINSTALL=1; shift ;;
    -h|--help)    usage ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$NAME" ] || { echo "ERROR: --name is required" >&2; exit 1; }
case "$NAME" in
  *[!A-Za-z0-9_.-]*) echo "ERROR: --name may only contain letters, digits, dots, hyphens and underscores" >&2; exit 1 ;;
esac

# Container engine: docker or podman. The error is written for operators whose
# first language may not be English, so it names exactly what to install.
ENGINE=""
if command -v docker >/dev/null 2>&1; then
  ENGINE="docker"
elif command -v podman >/dev/null 2>&1; then
  ENGINE="podman"
else
  echo "ERROR: neither 'docker' nor 'podman' was found on this machine." >&2
  echo "Please install Docker (https://docs.docker.com/engine/install/) or Podman (https://podman.io), then run this script again." >&2
  exit 1
fi

CONTAINER="oidx-connector-${NAME}"
VOLUME="${NAME}-data"

run() {
  if [ "${DRYRUN:-0}" = "1" ]; then
    echo "DRYRUN: $*"
  else
    "$@"
  fi
}

if [ "$UNINSTALL" = "1" ]; then
  run "$ENGINE" rm -f "$CONTAINER"
  echo "OK: removed container $CONTAINER. The enrolled identity is kept in volume $VOLUME;"
  echo "    remove it with: $ENGINE volume rm $VOLUME"
  exit 0
fi

[ -n "$TOKEN" ] || { echo "ERROR: --token is required (the enrollment JWT from the OpenIDX console)" >&2; exit 1; }
[ -n "$CTRL" ]  || { echo "ERROR: --ctrl is required (controller address as host:port)" >&2; exit 1; }

CTRL_HOST="${CTRL%%:*}"
CTRL_PORT="${CTRL##*:}"
if [ "$CTRL_HOST" = "$CTRL_PORT" ]; then CTRL_PORT="1280"; fi

# Idempotent: a container with the same name is replaced; the volume with the
# enrolled identity is kept, so re-running does not re-enroll.
if [ "${DRYRUN:-0}" != "1" ] && "$ENGINE" inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "Replacing existing container $CONTAINER (volume $VOLUME is kept)"
  "$ENGINE" rm -f "$CONTAINER" >/dev/null
fi

ARGS=(run -d --name "$CONTAINER" --restart=unless-stopped
  -v "$VOLUME:/ziti-router"
  -e "ZITI_ENROLL_TOKEN=$TOKEN"
  -e "ZITI_CTRL_ADVERTISED_ADDRESS=$CTRL_HOST"
  -e "ZITI_CTRL_ADVERTISED_PORT=$CTRL_PORT"
  -e "ZITI_ROUTER_MODE=host")
if [ -n "$ADVERTISED" ]; then
  # Public connector: other routers and clients dial it on 3022.
  ARGS+=(-p 3022:3022
    -e "ZITI_ROUTER_ADVERTISED_ADDRESS=$ADVERTISED"
    -e "ZITI_ROUTER_PORT=3022")
fi
ARGS+=("openziti/ziti-router:$IMAGE_TAG")

run "$ENGINE" "${ARGS[@]}"

if [ "${DRYRUN:-0}" = "1" ]; then
  exit 0
fi

echo "Waiting up to 60s for enrollment..."
deadline=$((SECONDS + 60))
while [ $SECONDS -lt $deadline ]; do
  logs=$("$ENGINE" logs "$CONTAINER" 2>&1 || true)
  if echo "$logs" | grep -qiE 'successfully enrolled|enrollment successful|registration complete'; then
    echo "OK: connector $CONTAINER enrolled and running."
    echo "    To remove it: $0 --name $NAME --uninstall"
    exit 0
  fi
  if echo "$logs" | grep -qiE 'enrollment.+(failed|error)|error.+enroll'; then
    echo "FAIL: enrollment failed. Last log lines:" >&2
    echo "$logs" | tail -20 >&2
    echo "Remove the failed install with: $0 --name $NAME --uninstall" >&2
    exit 1
  fi
  sleep 3
done
echo "FAIL: enrollment did not complete within 60s. Check: $ENGINE logs $CONTAINER" >&2
echo "Remove the install with: $0 --name $NAME --uninstall" >&2
exit 1
