#!/bin/sh
# Entrypoint for the PAM OpenZiti broker's ziti-tunnel sidecar.
#
# This container shares the ziti guacd's network namespace (compose
# `network_mode: service:pam-guacd-ziti`), so any loopback port it binds is the
# exact 127.0.0.1:<port> address guacd dials for a reach_mode='ziti' connection.
#
# It does two things:
#   1. Enroll the broker identity from a one-time token (JWT) if not yet enrolled.
#      The identity must carry the #pam-broker-dialers role so it may Dial the
#      per-entry PAM services (openidx-pam-<entryid>) OpenIDX provisions.
#   2. Run the tunneler, binding the loopback ports OpenIDX allocated per
#      ziti-enabled entry (the service->port map is served by the access-service
#      at $PAM_BROKER_BINDINGS_URL — GET /api/v1/access/pam/broker/ziti-bindings).
#
# NOTE (operator last mile): OpenIDX's reach mode uses proxy-loopback ports
# (host.v1 services, no intercept.v1), so the tunneler must PROXY each
# service->port pair. The exact proxy invocation is OpenZiti-tunneler-version
# specific, so it is centralized here and logged for visibility. Toggling a new
# ziti entry changes the binding set; re-run/restart this container (or wire the
# planned reconciler) to pick it up. See README.pam-broker.md.
set -eu

IDENTITY="${PAM_ZITI_IDENTITY:-/ziti-identity/pam-broker.json}"
ENROLL_TOKEN="${PAM_ZITI_ENROLL_TOKEN:-/ziti-identity/pam-broker.jwt}"
BINDINGS_URL="${PAM_BROKER_BINDINGS_URL:-http://access-service:8007/api/v1/access/pam/broker/ziti-bindings}"
BINDINGS_TOKEN="${PAM_BROKER_BINDINGS_TOKEN:-}"

log() { echo "[pam-ziti-tunnel] $*"; }

# 1. Enroll once if we have a token but no identity yet.
if [ ! -f "$IDENTITY" ] && [ -f "$ENROLL_TOKEN" ]; then
  log "enrolling broker identity from $ENROLL_TOKEN ..."
  ziti-edge-tunnel enroll --jwt "$ENROLL_TOKEN" --identity "$IDENTITY" || {
    log "enrollment failed; mount a pre-enrolled identity at $IDENTITY instead"
  }
fi

if [ ! -f "$IDENTITY" ]; then
  log "no identity at $IDENTITY — mount an enrolled #pam-broker-dialers identity (or a JWT at $ENROLL_TOKEN). Sleeping."
  # Stay up so the operator can exec in / mount the identity without a crash loop.
  while true; do sleep 3600; done
fi

# 2. Log the current service->loopback-port bindings for operator visibility.
if command -v curl >/dev/null 2>&1; then
  log "current PAM ziti bindings (service -> loopback port):"
  if [ -n "$BINDINGS_TOKEN" ]; then
    curl -fsS -H "Authorization: Bearer $BINDINGS_TOKEN" "$BINDINGS_URL" || log "  (could not fetch $BINDINGS_URL)"
  else
    curl -fsS "$BINDINGS_URL" || log "  (bindings endpoint is admin-guarded; set PAM_BROKER_BINDINGS_TOKEN)"
  fi
  echo
fi

# 3. Run the tunneler. `run` serves any intercept-configured services the identity
# can dial; proxy-loopback binding for host.v1 services is the documented operator
# last mile (README.pam-broker.md) — override this command to add explicit
# `proxy` bindings for your OpenZiti tunneler version.
log "starting ziti-edge-tunnel for identity $IDENTITY"
exec ziti-edge-tunnel run --identity "$IDENTITY"
