#!/usr/bin/env bash
# dark-mode.sh — operate and VERIFY the "dark platform" posture
# (docs/superpowers/specs/2026-07-17-dark-platform-ziti-first-design.md).
#
# The whole point of dark mode is the two-sided invariant, per surface:
#   - PUBLIC path is REFUSED (its edge route is gone / the service is loopback-bound), and
#   - OVERLAY path is REACHABLE (an enrolled+trusted identity gets through), and
#   - the TIER GATE holds (a Tier-1-only identity is refused a Tier-2 surface).
# Never drop a public route until --verify proves the overlay path works: a
# botched cutover locks admins out of the platform that manages the overlay.
#
# MODES
#   --verify        Assert the invariant against a live deployment. Needs
#                   --public-url and --overlay-url (how you reach a darked
#                   surface publicly vs over the overlay).
#   --self-test     Stand up local mocks (public server that 404s the mgmt path,
#                   overlay server that 200s it) and run --verify against them.
#                   No infra; proves the verdict logic can't silently rot. This
#                   is what `make dark-drill` runs.
#   --undark        BREAK-GLASS: re-seed the public routes (DARK_MODE=off) and
#                   print the loopback-bind revert, restoring the prior public
#                   posture in one command from the host shell.
#
# USAGE
#   scripts/dark-mode.sh --self-test
#   scripts/dark-mode.sh --verify \
#       --public-url  https://openidx.tdv.org/api/v1/admin/health \
#       --overlay-url http://127.0.0.1:8005/health/live
#   scripts/dark-mode.sh --undark
#
# EXIT 0 = invariant holds (or undark done); 1 = violation; 2 = usage.
set -euo pipefail

MODE=""
PUBLIC_URL=""
OVERLAY_URL=""
SELF_TEST=0
POLL_TIMEOUT=4

usage() { sed -n '2,32p' "$0"; exit "${1:-2}"; }

while [ $# -gt 0 ]; do
	case "$1" in
		--verify) MODE=verify ;;
		--undark) MODE=undark ;;
		--self-test) SELF_TEST=1; MODE=verify ;;
		--public-url) PUBLIC_URL="$2"; shift ;;
		--overlay-url) OVERLAY_URL="$2"; shift ;;
		-h|--help) usage 0 ;;
		*) echo "unknown arg: $1" >&2; usage 2 ;;
	esac
	shift
done
[ -n "$MODE" ] || { echo "need --verify, --self-test, or --undark" >&2; usage 2; }

log()  { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '❌ %s\n' "$*" >&2; exit 1; }
ok()   { printf '  ✓ %s\n' "$*"; }

# probe: echo the HTTP status (000 = refused/timeout, i.e. dark).
probe() { curl -s -o /dev/null -m "$POLL_TIMEOUT" -w '%{http_code}' "$1" 2>/dev/null || echo 000; }

# ----------------------------- break-glass ---------------------------------
if [ "$MODE" = "undark" ]; then
	log "🔦 BREAK-GLASS: restoring the public posture (DARK_MODE=off)"
	repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
	seeder="$repo_root/deployments/apisix-edge/seed-edge-routes.sh"
	if [ -x "$seeder" ] || [ -f "$seeder" ]; then
		log "re-seeding edge routes with DARK_MODE=off ..."
		DARK_MODE=off bash "$seeder" || fail "route re-seed failed — check APISIX admin reachability"
		ok "public edge routes restored"
	else
		log "  (seeder not found at $seeder — re-seed the edge routes manually)"
	fi
	echo ""
	echo "  Also revert the loopback bind on each service and restart:"
	echo "    unset SERVICE_BIND_ADDR DARK_MODE_TIER1 DARK_MODE_TIER2   # (or set them empty/false)"
	echo "    systemctl --user restart oidx-admin-api oidx-governance oidx-audit \\"
	echo "        oidx-provisioning oidx-access oidx-identity oidx-oauth"
	log "✅ undark complete — the platform is public again."
	exit 0
fi

# ----------------------------- self-test mocks -----------------------------
MOCK_PIDS=()
start_mocks() {
	command -v python3 >/dev/null 2>&1 || fail "self-test needs python3"
	# PUBLIC mock: a darked mgmt surface returns 404 (route gone); the enroll
	# door returns 200 (Tier 0 stays public).
	python3 - 18701 <<'PY' &
import http.server,socketserver,sys
port=int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def _s(self,c): self.send_response(c); self.end_headers()
    def do_GET(self):
        if self.path.startswith("/api/v1/access/enroll"): self._s(200)
        else: self._s(404)   # darked mgmt path: no public route
    def log_message(self,*a): pass
socketserver.TCPServer(("127.0.0.1",port),H).serve_forever()
PY
	MOCK_PIDS+=($!)
	# OVERLAY mock: the same mgmt surface IS reachable over the overlay (200);
	# a Tier-1-only caller (header X-Tier: 1) is refused a Tier-2 path (403).
	python3 - 18702 <<'PY' &
import http.server,socketserver,sys
port=int(sys.argv[1])
class H(http.server.BaseHTTPRequestHandler):
    def _s(self,c): self.send_response(c); self.end_headers()
    def do_GET(self):
        if self.headers.get("X-Tier")=="1": self._s(403)  # tier gate: T1 can't reach T2
        else: self._s(200)
    def log_message(self,*a): pass
socketserver.TCPServer(("127.0.0.1",port),H).serve_forever()
PY
	MOCK_PIDS+=($!)
	sleep 1
	PUBLIC_URL="http://127.0.0.1:18701/api/v1/admin/health"
	OVERLAY_URL="http://127.0.0.1:18702/api/v1/admin/health"
}
stop_mocks() { for p in "${MOCK_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap stop_mocks EXIT

# ----------------------------- verify --------------------------------------
if [ "$SELF_TEST" -eq 1 ]; then
	log "🧪 dark-mode SELF-TEST (mock public + overlay, no infra)"
	start_mocks
else
	log "🌑 dark-mode --verify (live)"
	[ -n "$PUBLIC_URL" ] && [ -n "$OVERLAY_URL" ] || { echo "need --public-url and --overlay-url" >&2; usage 2; }
fi

rc=0
log "── verifying dark invariant ──"

# 1. Public path must be refused (route gone) or a non-2xx (never reachable).
pub=$(probe "$PUBLIC_URL")
if [ "$pub" = "000" ] || [ "$pub" = "404" ] || [ "$pub" = "403" ]; then
	ok "public path refused ($pub) — surface is dark to the internet"
else
	echo "  ❌ public path still reachable ($pub): $PUBLIC_URL — the management surface is NOT dark"
	rc=1
fi

# 2. Overlay path must be reachable for an enrolled identity.
ov=$(probe "$OVERLAY_URL")
if [ "$ov" = "200" ]; then
	ok "overlay path reachable (200) — enrolled identity gets through"
else
	echo "  ❌ overlay path NOT reachable ($ov): $OVERLAY_URL — a bad cutover would lock everyone out"
	rc=1
fi

# 3. Tier gate: a Tier-1-only identity must be refused a Tier-2 surface.
t1=$(curl -s -o /dev/null -m "$POLL_TIMEOUT" -w '%{http_code}' -H 'X-Tier: 1' "$OVERLAY_URL" 2>/dev/null || echo 000)
if [ "$t1" = "403" ] || [ "$t1" = "401" ] || [ "$t1" = "000" ]; then
	ok "tier gate holds — a Tier-1-only identity is refused the Tier-2 surface ($t1)"
else
	echo "  ❌ tier gate BROKEN: a Tier-1-only identity reached the Tier-2 surface ($t1)"
	rc=1
fi

echo ""
if [ "$rc" -eq 0 ]; then
	log "✅ dark-mode invariant holds (public refused / overlay reachable / tier gate holds)"
else
	log "❌ dark-mode invariant VIOLATED — do NOT drop public routes; investigate above."
fi
exit "$rc"
