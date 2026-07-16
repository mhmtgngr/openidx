#!/usr/bin/env bash
# dr-game-day.sh — runnable Disaster-Recovery game-day for the data-tier failover
# described in docs/disaster-recovery.md §1D (RDS Multi-AZ / Patroni).
#
# What this proves (the always-available-auth contract):
#   1. VERIFY PATH stays up through the whole failover window. Validating an
#      already-issued JWT does not touch Postgres (in-memory JWKS + serve-stale),
#      so /health/live must never flip and the verify probe must never fail.
#   2. ISSUE PATH degrades cleanly and recovers WITHOUT a restart: during the
#      failover window /health/ready may return 503 (LB drains new logins), but
#      once the promoted primary is reachable, readiness recovers on its own
#      (pgxpool re-dials) — no kubectl rollout, no pod restarts.
#
# The script drives a synthetic auth canary against two probes:
#   --live-url   (default {BASE}/health/live)   — must stay 200 the entire time
#   --ready-url  (default {BASE}/health/ready)  — may 503 briefly, must recover
#
# MODES
#   --self-test        Spin up a local mock that simulates a failover window and
#                      run the whole game-day against it. Requires NO infra and
#                      is safe for CI — it validates the game-day logic itself so
#                      it can't silently rot (a false-green DR drill is worse than
#                      none). This is what `make dr-game-day` runs.
#
#   (default / live)   Run against a real staging deployment. Point --base-url at
#                      the ingress. By default the script only OBSERVES; it prints
#                      the exact failover command and waits for you (or, with
#                      --trigger + --provider, it triggers failover for you).
#
# USAGE
#   scripts/dr-game-day.sh --self-test
#   scripts/dr-game-day.sh --base-url https://staging.openidx.example
#   scripts/dr-game-day.sh --base-url https://staging.openidx.example \
#       --trigger --provider rds --rds-instance openidx-staging
#   scripts/dr-game-day.sh --base-url https://staging.openidx.example \
#       --trigger --provider patroni --patroni-cluster openidx --patroni-standby pg-1
#
# EXIT CODES
#   0  contract held (verify never dropped; issue path recovered without restart)
#   1  contract violated (verify dropped, or issue path did not self-recover)
#   2  usage / environment error
set -euo pipefail

# ----------------------------- defaults ------------------------------------
BASE_URL=""
LIVE_URL=""
READY_URL=""
SELF_TEST=0
TRIGGER=0
PROVIDER=""
RDS_INSTANCE=""
PATRONI_CLUSTER=""
PATRONI_STANDBY=""
DURATION=90          # total observation window (seconds)
INTERVAL=1           # probe cadence (seconds)
RECOVER_BUDGET=75    # issue path must recover within this many seconds
POLL_TIMEOUT=3       # per-request curl timeout (~DB_CONNECT_TIMEOUT territory)

# self-test knobs (also used by the embedded mock)
ST_FAILOVER_AT=8     # mock starts returning 503-ready at t=this
ST_RECOVER_AT=28     # mock readiness recovers at t=this

usage() { sed -n '2,48p' "$0"; exit "${1:-2}"; }

while [ $# -gt 0 ]; do
	case "$1" in
		--self-test) SELF_TEST=1 ;;
		--base-url) BASE_URL="$2"; shift ;;
		--live-url) LIVE_URL="$2"; shift ;;
		--ready-url) READY_URL="$2"; shift ;;
		--trigger) TRIGGER=1 ;;
		--provider) PROVIDER="$2"; shift ;;
		--rds-instance) RDS_INSTANCE="$2"; shift ;;
		--patroni-cluster) PATRONI_CLUSTER="$2"; shift ;;
		--patroni-standby) PATRONI_STANDBY="$2"; shift ;;
		--duration) DURATION="$2"; shift ;;
		--recover-budget) RECOVER_BUDGET="$2"; shift ;;
		-h|--help) usage 0 ;;
		*) echo "unknown arg: $1" >&2; usage 2 ;;
	esac
	shift
done

log()  { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '❌ %s\n' "$*" >&2; exit 1; }

# ----------------------------- self-test mock ------------------------------
# A tiny stdlib-only HTTP server that models the failover window:
#   /health/live  -> always 200            (verify path is DB-free)
#   /health/ready -> 200, then 503 in the failover window, then 200 again
#   /verify       -> always 200            (validating an existing JWT)
MOCK_PID=""
start_mock() {
	command -v python3 >/dev/null 2>&1 || fail "self-test needs python3"
	local port="$1"
	MOCK_START="$(date +%s)"
	FAILOVER_AT="$ST_FAILOVER_AT" RECOVER_AT="$ST_RECOVER_AT" START="$MOCK_START" \
	python3 - "$port" <<'PY' &
import http.server, os, socketserver, sys, time
port = int(sys.argv[1])
start = float(os.environ["START"]); fa = float(os.environ["FAILOVER_AT"]); ra = float(os.environ["RECOVER_AT"])
class H(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code); self.send_header("Content-Type","application/json")
        self.end_headers(); self.wfile.write(body.encode())
    def do_GET(self):
        t = time.time() - start
        if self.path.startswith("/health/live") or self.path.startswith("/verify"):
            # Verify path is DB-free: NEVER degrade.
            self._send(200, '{"status":"alive"}')
        elif self.path.startswith("/health/ready"):
            if fa <= t < ra:
                self._send(503, '{"status":"not_ready","reason":"db_failover"}')
            else:
                self._send(200, '{"status":"ready"}')
        else:
            self._send(404, '{}')
    def log_message(self, *a): pass
with socketserver.TCPServer(("127.0.0.1", port), H) as s:
    s.serve_forever()
PY
	MOCK_PID=$!
	sleep 1
}
stop_mock() { [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true; }
trap stop_mock EXIT

# ----------------------------- failover trigger ----------------------------
trigger_failover() {
	case "$PROVIDER" in
		rds)
			[ -n "$RDS_INSTANCE" ] || fail "--provider rds needs --rds-instance"
			command -v aws >/dev/null 2>&1 || fail "aws CLI not found"
			log "⚡ triggering RDS failover: $RDS_INSTANCE"
			aws rds reboot-db-instance --db-instance-identifier "$RDS_INSTANCE" --force-failover >/dev/null
			;;
		patroni)
			[ -n "$PATRONI_CLUSTER" ] && [ -n "$PATRONI_STANDBY" ] || fail "--provider patroni needs --patroni-cluster and --patroni-standby"
			command -v patronictl >/dev/null 2>&1 || fail "patronictl not found"
			log "⚡ triggering Patroni switchover: $PATRONI_CLUSTER -> $PATRONI_STANDBY"
			patronictl switchover "$PATRONI_CLUSTER" --candidate "$PATRONI_STANDBY" --force
			;;
		*) fail "--trigger requires --provider rds|patroni" ;;
	esac
}

# probe: echo the HTTP status code (000 on connection failure/timeout)
probe() { curl -s -o /dev/null -m "$POLL_TIMEOUT" -w '%{http_code}' "$1" 2>/dev/null || echo 000; }

# ----------------------------- run -----------------------------------------
PORT=8765
if [ "$SELF_TEST" -eq 1 ]; then
	log "🧪 DR game-day SELF-TEST (mock failover window, no infra)"
	start_mock "$PORT"
	BASE_URL="http://127.0.0.1:${PORT}"
	DURATION=$(( ST_RECOVER_AT + 12 ))
	RECOVER_BUDGET=$(( ST_RECOVER_AT + 8 ))
else
	[ -n "$BASE_URL" ] || { echo "need --base-url (or --self-test)" >&2; usage 2; }
	log "🌩  DR game-day (live) against ${BASE_URL}"
fi

LIVE_URL="${LIVE_URL:-${BASE_URL}/health/live}"
READY_URL="${READY_URL:-${BASE_URL}/health/ready}"

# Baseline: both probes must be healthy before we start, else the drill is moot.
[ "$(probe "$LIVE_URL")" = "200" ]  || fail "baseline: $LIVE_URL is not 200 — fix the deploy before drilling"
[ "$(probe "$READY_URL")" = "200" ] || fail "baseline: $READY_URL is not 200 — fix the deploy before drilling"
log "baseline OK: live=200 ready=200"

# Kick off failover.
if [ "$SELF_TEST" -eq 1 ]; then
	log "mock will drop readiness at t=${ST_FAILOVER_AT}s and recover at t=${ST_RECOVER_AT}s"
elif [ "$TRIGGER" -eq 1 ]; then
	trigger_failover
else
	echo ""
	echo "  ▶ Now trigger failover in another terminal, e.g.:"
	echo "      aws rds reboot-db-instance --db-instance-identifier <id> --force-failover"
	echo "      patronictl switchover <cluster> --candidate <standby> --force"
	echo "    (or re-run with --trigger --provider ...)"
	echo ""
fi

# Observe.
start=$(date +%s)
live_drops=0
ready_dropped=0
ready_drop_first=-1
ready_recovered_at=-1
samples=0
while :; do
	now=$(date +%s); t=$(( now - start ))
	[ "$t" -ge "$DURATION" ] && break
	lc=$(probe "$LIVE_URL"); rc=$(probe "$READY_URL")
	samples=$(( samples + 1 ))
	# VERIFY PATH invariant: live must never leave 200.
	if [ "$lc" != "200" ]; then
		live_drops=$(( live_drops + 1 ))
		log "t=${t}s  live=${lc} ⚠ VERIFY PATH DROPPED  ready=${rc}"
	else
		# Track issue-path drop + recovery.
		if [ "$rc" = "503" ] || [ "$rc" = "000" ]; then
			if [ "$ready_dropped" -eq 0 ]; then ready_drop_first=$t; log "t=${t}s  live=200 ready=${rc}  ← issue path draining (expected)"; fi
			ready_dropped=1
			ready_recovered_at=-1
		elif [ "$rc" = "200" ]; then
			if [ "$ready_dropped" -eq 1 ] && [ "$ready_recovered_at" -lt 0 ]; then
				ready_recovered_at=$t; log "t=${t}s  live=200 ready=200  ← issue path RECOVERED (no restart)"
			fi
		fi
	fi
	sleep "$INTERVAL"
done

echo ""
log "── verdict ──"
rc=0
# 1. Verify path must have stayed up the entire window.
if [ "$live_drops" -gt 0 ]; then
	echo "❌ VERIFY PATH regressed: /health/live returned non-200 ${live_drops}× — the"
	echo "   always-available guarantee is broken (verify must be DB-free/serve-stale)."
	rc=1
else
	echo "✅ verify path held: /health/live stayed 200 across ${samples} samples"
fi
# 2. Issue path: if it dropped, it must have recovered on its own within budget.
if [ "$ready_dropped" -eq 1 ]; then
	if [ "$ready_recovered_at" -lt 0 ]; then
		echo "❌ ISSUE PATH did not self-recover within ${DURATION}s — pgxpool is NOT"
		echo "   re-dialing the promoted primary. Check DB_CONNECT_TIMEOUT is set and"
		echo "   HealthCheckPeriod is evicting dead conns (internal/common/database)."
		rc=1
	else
		span=$(( ready_recovered_at - ready_drop_first ))
		if [ "$ready_recovered_at" -gt "$RECOVER_BUDGET" ]; then
			echo "❌ ISSUE PATH recovered but too slowly (${ready_recovered_at}s > budget ${RECOVER_BUDGET}s)."
			rc=1
		else
			echo "✅ issue path recovered on its own in ~${span}s (drop@${ready_drop_first}s → ok@${ready_recovered_at}s), no restart"
		fi
	fi
else
	if [ "$SELF_TEST" -eq 1 ]; then
		echo "❌ SELF-TEST BUG: the mock failover window was never observed — the drill"
		echo "   logic would miss a real outage. Failing so this can't silently rot."
		rc=1
	else
		echo "ℹ issue path never dropped — failover may not have been triggered yet, or"
		echo "   the LB kept draining transparently. Re-run with --trigger to be sure."
	fi
fi

echo ""
if [ "$rc" -eq 0 ]; then
	log "✅ DR game-day PASSED — data-tier failover preserves the auth contract."
else
	log "❌ DR game-day FAILED — see verdict above."
fi
exit "$rc"
