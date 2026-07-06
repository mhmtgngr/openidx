#!/usr/bin/env bash
# OpenIDX edge-router entrypoint: run the router from the version-controlled
# config (mounted at /etc/ziti/router-config.yml) instead of generating one in
# the container and patching it with sed/awk.
#
# First start: copy the config into the router volume and enroll with the JWT
# minted by ziti-router-init. Restarts: the copy in the volume is authoritative
# (the enrolled identity's CSR SANs came from it — replacing it under an
# existing identity could break TLS), so it is only written when absent.
# To pick up config changes on an already-enrolled router: edit the copy in
# the ziti_router_data volume, or remove the volume to re-enroll cleanly.
set -euo pipefail

# bootstrap.bash (from the base image) logs to fd 3
exec 3>/dev/null

CONFIG="config.yml"
SOURCE_CONFIG="/etc/ziti/router-config.yml"

if [[ ! -s "$CONFIG" ]]; then
  echo "==> Installing router config from $SOURCE_CONFIG"
  cp "$SOURCE_CONFIG" "$CONFIG"
fi

# The base image's bootstrap provides the idempotent enroll() helper.
source /bootstrap.bash
if [[ "${ZITI_BOOTSTRAP_ENROLLMENT:-}" == true ]]; then
  enroll "$CONFIG"
fi

echo "==> Starting router"
exec ziti router run "$CONFIG"
