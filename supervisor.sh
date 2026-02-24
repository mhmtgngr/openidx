#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#
#  SUPERVISOR — Self-Healing Controller for team.sh
#  ─────────────────────────────────────────────────
#  Monitors team.sh, detects failures, auto-fixes, resumes.
#  Can patch team.sh itself when bugs are found.
#
#  FEATURES:
#    🔄 Auto-restart on crash
#    🩺 Health check every 60s
#    🔧 Auto-skip stuck phases
#    📝 Patch team.sh bugs on the fly
#    ⏰ Timeout detection (phase stuck too long)
#    📊 Progress dashboard
#    🔁 Retry with smaller prompts on OOM/terminate
#
#  USAGE:
#    ./supervisor.sh start "project description"
#    ./supervisor.sh watch              # attach to running
#    ./supervisor.sh status             # dashboard
#    ./supervisor.sh skip [phase]       # skip stuck phase
#    ./supervisor.sh restart            # stop + resume
#    ./supervisor.sh stop               # stop everything
#    ./supervisor.sh patch "fix desc"   # patch team.sh
#    ./supervisor.sh improve            # run improvement cycle
#
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

# Load PATH
for rc in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [ -f "$rc" ] && source "$rc" 2>/dev/null || true
done
export PATH="$HOME/go/bin:$HOME/.local/bin:$HOME/.npm-global/bin:/usr/local/go/bin:/usr/local/bin:$PATH"

# ═══════════════════════════════════
# CONFIG
# ═══════════════════════════════════

REPO_DIR="$PWD"
TEAM_SH="$REPO_DIR/team.sh"
TEAM_DIR="$REPO_DIR/.team"
STATE_FILE="$TEAM_DIR/state.json"
LIVE_LOG="$TEAM_DIR/live.log"
SUP_LOG="$TEAM_DIR/supervisor.log"
SUP_PID="$TEAM_DIR/supervisor.pid"
PATCHES_DIR="$TEAM_DIR/patches"
PLAN_FILE="$TEAM_DIR/artifacts/next_phases.json"
PHASE_HISTORY="$TEAM_DIR/phase_history.json"

CLAUDE_MODEL="${CLAUDE_MODEL:-opus}"

# Timeouts per phase (seconds)
declare -A PHASE_TIMEOUT=(
  [requirements]=600    # 10 min
  [market_research]=900 # 15 min
  [design]=900          # 15 min
  [backend]=3600        # 60 min
  [frontend]=3600       # 60 min
  [testing]=2400        # 40 min
  [qa]=600              # 10 min
  [security]=600        # 10 min
  [deploy]=1800         # 30 min
)

MAX_PHASE_RETRIES=2
MAX_CRASHES=5
HEALTH_INTERVAL=60

# Colors
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'
B='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; NC='\033[0m'

mkdir -p "$TEAM_DIR" "$PATCHES_DIR"
touch "$SUP_LOG" "$LIVE_LOG"

slog() { echo -e "${G}[SUP $(date '+%H:%M:%S')]${NC} $1" | tee -a "$SUP_LOG"; }
swarn() { echo -e "${Y}[SUP $(date '+%H:%M:%S')]${NC} $1" | tee -a "$SUP_LOG"; }
serr() { echo -e "${R}[SUP $(date '+%H:%M:%S')]${NC} $1" | tee -a "$SUP_LOG"; }

# ═══════════════════════════════════
# STATE HELPERS
# ═══════════════════════════════════

get_state() {
  python3 - "$STATE_FILE" "$1" "$2" << 'PYEOF' 2>/dev/null
import json, os, sys
f, phase, key = sys.argv[1], sys.argv[2], sys.argv[3]
if not os.path.exists(f): print(""); exit()
d = json.load(open(f))
if phase == "_meta":
    print(d.get(key, ""))
else:
    print(d.get("phases", {}).get(phase, {}).get(key, ""))
PYEOF
}

set_state() {
  python3 - "$STATE_FILE" "$1" "$2" "$3" << 'PYEOF' 2>/dev/null
import json, os, sys
from datetime import datetime
f, phase, key, val = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
d = json.load(open(f)) if os.path.exists(f) else {"phases": {}}
if phase == "_meta":
    d[key] = val
else:
    d.setdefault("phases", {}).setdefault(phase, {})[key] = val
    d["phases"][phase]["_updated"] = datetime.now().isoformat()
json.dump(d, open(f, "w"), indent=2)
PYEOF
}

current_phase() {
  get_state _meta current_phase
}

phase_status() {
  get_state "$1" status
}

phase_updated() {
  get_state "$1" _updated
}

# ═══════════════════════════════════
# TEAM.SH CONTROL
# ═══════════════════════════════════

team_is_running() {
  [ -f "$TEAM_DIR/team.pid" ] && kill -0 "$(cat "$TEAM_DIR/team.pid" 2>/dev/null)" 2>/dev/null
}

team_start() {
  local project="$1"
  slog "Starting team.sh: $project"
  cd "$REPO_DIR"
  bash "$TEAM_SH" --project "$project" &
  sleep 3
  if team_is_running; then
    slog "✓ team.sh running (PID: $(cat "$TEAM_DIR/team.pid"))"
  else
    serr "✗ team.sh failed to start"
    return 1
  fi
}

team_resume() {
  slog "Resuming team.sh..."
  cd "$REPO_DIR"
  bash "$TEAM_SH" --resume &
  sleep 3
  if team_is_running; then
    slog "✓ team.sh resumed (PID: $(cat "$TEAM_DIR/team.pid"))"
  else
    serr "✗ team.sh failed to resume"
    return 1
  fi
}

team_stop() {
  slog "Stopping team.sh..."
  cd "$REPO_DIR"
  bash "$TEAM_SH" --stop 2>/dev/null || true
  pkill -f "claude.*dangerously-skip-permissions" 2>/dev/null || true
  sleep 2
  slog "✓ Stopped"
}

# ═══════════════════════════════════
# SKIP PHASE
# ═══════════════════════════════════

skip_phase() {
  local phase="${1:-$(current_phase)}"
  swarn "Skipping phase: $phase"

  team_stop

  # Mark current phase done, advance to next
  set_state "$phase" status done

  local phases=(requirements market_research design backend frontend testing qa security deploy)
  local next=""
  local found=false
  for p in "${phases[@]}"; do
    if [ "$found" = true ]; then next="$p"; break; fi
    [ "$p" = "$phase" ] && found=true
  done

  if [ -n "$next" ]; then
    set_state _meta current_phase "$next"
    slog "Advanced to: $next"
    team_resume
  else
    slog "All phases complete"
  fi
}

# ═══════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════

check_phase_timeout() {
  local phase; phase=$(current_phase)
  [ -z "$phase" ] && return 0

  local updated; updated=$(phase_updated "$phase")
  [ -z "$updated" ] && return 0

  local timeout=${PHASE_TIMEOUT[$phase]:-3600}

  local updated_ts
  updated_ts=$(python3 -c "
from datetime import datetime
try:
    dt = datetime.fromisoformat('$updated')
    print(int(dt.timestamp()))
except:
    print(0)
" 2>/dev/null || echo "0")

  local now_ts; now_ts=$(date +%s)
  local elapsed=$((now_ts - updated_ts))

  if [ "$elapsed" -gt "$timeout" ]; then
    swarn "Phase '$phase' stuck for ${elapsed}s (timeout: ${timeout}s)"
    return 1
  fi
  return 0
}

check_live_log_stale() {
  # Check if live log hasn't been written to in 5 minutes
  if [ -f "$LIVE_LOG" ]; then
    local last_mod
    last_mod=$(stat -c %Y "$LIVE_LOG" 2>/dev/null || echo "0")
    local now; now=$(date +%s)
    local diff=$((now - last_mod))
    if [ "$diff" -gt 300 ]; then
      swarn "Live log stale for ${diff}s"
      return 1
    fi
  fi
  return 0
}

check_terminated() {
  # Check if last log lines show "Terminated"
  if tail -5 "$LIVE_LOG" 2>/dev/null | grep -q "Terminated"; then
    swarn "Detected 'Terminated' in log"
    return 0
  fi
  return 1
}

check_error_pattern() {
  # Check for known error patterns in last 20 lines
  local errors
  errors=$(tail -20 "$LIVE_LOG" 2>/dev/null | grep -i "command not found\|permission denied\|no space left\|ENOMEM\|Killed\|OOM\|panic:\|FATAL\|segfault" || true)
  if [ -n "$errors" ]; then
    swarn "Error pattern detected: $(echo "$errors" | head -1)"
    return 0
  fi
  return 1
}

# ═══════════════════════════════════
# SELF-HEALING ACTIONS
# ═══════════════════════════════════

heal_terminated() {
  local phase; phase=$(current_phase)
  slog "🩺 Healing terminated phase: $phase"

  local retries
  retries=$(get_state "$phase" _retries)
  retries=$((${retries:-0} + 1))
  set_state "$phase" _retries "$retries"

  if [ "$retries" -gt "$MAX_PHASE_RETRIES" ]; then
    swarn "Phase '$phase' failed $retries times — skipping"
    skip_phase "$phase"
    return
  fi

  # Strategy 1: Just restart (transient failure)
  if [ "$retries" -eq 1 ]; then
    slog "  Strategy: simple restart"
    team_stop; sleep 5; team_resume
    return
  fi

  # Strategy 2: Reset phase and retry
  if [ "$retries" -eq 2 ]; then
    slog "  Strategy: reset phase + restart"
    team_stop
    set_state "$phase" status pending
    sleep 5
    team_resume
    return
  fi
}

heal_stuck() {
  local phase; phase=$(current_phase)
  slog "🩺 Healing stuck phase: $phase"
  team_stop
  sleep 3

  # Check if the phase actually made progress
  local status; status=$(phase_status "$phase")
  if [ "$status" = "running" ]; then
    swarn "  Phase was running but got stuck — restarting"
    team_resume
  else
    swarn "  Phase stuck in state: $status — skipping"
    skip_phase "$phase"
  fi
}

heal_error() {
  local phase; phase=$(current_phase)
  local error_line
  error_line=$(tail -20 "$LIVE_LOG" 2>/dev/null | grep -i "command not found\|permission denied\|ENOMEM\|Killed" | head -1 || true)

  slog "🩺 Healing error in phase '$phase': $error_line"

  # PATH issues
  if echo "$error_line" | grep -qi "command not found"; then
    local missing_cmd
    missing_cmd=$(echo "$error_line" | grep -oP '\S+(?=: command not found)' || true)
    swarn "  Missing command: $missing_cmd"

    case "$missing_cmd" in
      go)
        slog "  Fixing: go not in PATH"
        patch_team "Add go to PATH" 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"'
        ;;
      node|npm|npx)
        slog "  Fixing: node not in PATH"
        patch_team "Add node to PATH" 'export PATH="$HOME/.nvm/versions/node/$(ls $HOME/.nvm/versions/node/ 2>/dev/null | tail -1)/bin:$PATH"'
        ;;
      *)
        swarn "  Unknown missing command: $missing_cmd — skipping phase"
        skip_phase "$phase"
        return
        ;;
    esac
    team_stop; sleep 3; team_resume
    return
  fi

  # OOM / Killed
  if echo "$error_line" | grep -qi "ENOMEM\|Killed\|OOM"; then
    swarn "  Out of memory — skipping phase"
    skip_phase "$phase"
    return
  fi

  # Generic: restart
  team_stop; sleep 5; team_resume
}

# ═══════════════════════════════════
# PATCH TEAM.SH
# ═══════════════════════════════════

patch_team() {
  local desc="$1" code="$2"
  local patch_file="$PATCHES_DIR/$(date +%s)_$(echo "$desc" | tr ' ' '_' | tr -cd 'a-zA-Z0-9_').patch"

  slog "📝 Patching team.sh: $desc"

  # Backup
  cp "$TEAM_SH" "$TEAM_SH.bak.$(date +%s)"

  # Apply patch
  echo "$code" > "$patch_file"

  # Insert after the PATH loading block (line ~10)
  if ! grep -qF "$code" "$TEAM_SH"; then
    sed -i "/^export PATH=.*HOME.*go/a\\$code" "$TEAM_SH" 2>/dev/null || {
      # Fallback: add after set -euo pipefail
      sed -i "/^set -euo pipefail$/a\\$code" "$TEAM_SH"
    }
    slog "  ✓ Patched"
  else
    slog "  ↳ Already patched"
  fi
}

patch_team_with_claude() {
  local problem="$1"
  slog "🤖 Asking Claude to fix team.sh: $problem"

  team_stop

  cd "$REPO_DIR"
  local fix_log="$TEAM_DIR/logs/sup_patch.log"

  claude -p --model "$CLAUDE_MODEL" --dangerously-skip-permissions \
    "Read the file team.sh in the current directory.

PROBLEM: $problem

Fix the bug in team.sh. The script uses 'set -euo pipefail' so any pipe returning non-zero kills the script.
Common fixes:
- Add '|| true' to grep/find pipes that might return empty
- Use variable=\$(cmd || true) pattern
- Don't use PIPESTATUS with pipefail
- Add '|| rc=\$?' pattern for commands that might fail

Make MINIMAL changes. Only fix the specific bug. Test with 'bash -n team.sh'." \
    > "$fix_log" 2>&1 || true

  # Verify syntax
  if bash -n "$TEAM_SH" 2>/dev/null; then
    slog "  ✓ Claude patched team.sh successfully"
  else
    serr "  ✗ Claude broke team.sh — restoring backup"
    local latest_bak
    latest_bak=$(ls -t "$TEAM_SH".bak.* 2>/dev/null | head -1)
    [ -n "$latest_bak" ] && cp "$latest_bak" "$TEAM_SH"
  fi

  team_resume
}

# ═══════════════════════════════════
# IMPROVEMENT CYCLE
# ═══════════════════════════════════

# ═══════════════════════════════════
# PHASE PLANNER — Decides What's Next
# ═══════════════════════════════════

AUTO_PHASES="${AUTO_PHASES:-3}"

init_phase_history() {
  [ -f "$PHASE_HISTORY" ] || echo '{"completed":[],"current_round":0}' > "$PHASE_HISTORY"
}

record_completed_round() {
  local desc="$1"
  python3 - "$PHASE_HISTORY" "$desc" << 'PYEOF'
import json, sys
from datetime import datetime
f, desc = sys.argv[1], sys.argv[2]
d = json.load(open(f)) if __import__('os').path.exists(f) else {"completed":[],"current_round":0}
d["completed"].append({"description": desc, "timestamp": datetime.now().isoformat()})
d["current_round"] = len(d["completed"])
json.dump(d, open(f, "w"), indent=2)
PYEOF
}

plan_next_phases() {
  slog "🧠 Planning next $AUTO_PHASES phases..."

  init_phase_history
  local history
  history=$(cat "$PHASE_HISTORY" 2>/dev/null || echo "{}")
  local project_context
  project_context=$(head -c 3000 "$REPO_DIR/CLAUDE.md" 2>/dev/null || echo "No CLAUDE.md")

  # Gather current project state
  local go_files; go_files=$(find "$REPO_DIR/internal" "$REPO_DIR/cmd" -name "*.go" 2>/dev/null | wc -l || echo "0")
  local test_files; test_files=$(find "$REPO_DIR" -name "*_test.go" 2>/dev/null | wc -l || echo "0")
  local tsx_files; tsx_files=$(find "$REPO_DIR/frontend/src" -name "*.tsx" -o -name "*.ts" 2>/dev/null | wc -l || echo "0")
  local todo_count; todo_count=$(grep -r "TODO\|FIXME\|HACK\|XXX" "$REPO_DIR/internal" "$REPO_DIR/cmd" "$REPO_DIR/frontend/src" 2>/dev/null | wc -l || echo "0")
  local build_ok="unknown"
  cd "$REPO_DIR"
  go build ./... 2>/dev/null && build_ok="yes" || build_ok="no"
  local test_ok="unknown"
  go test ./... -count=1 -timeout 60s 2>/dev/null && test_ok="pass" || test_ok="fail"

  local compile_errors=""
  if [ "$build_ok" = "no" ]; then
    compile_errors=$(go build ./... 2>&1 | tail -20 || true)
  fi
  local test_failures=""
  if [ "$test_ok" = "fail" ]; then
    test_failures=$(go test ./... -count=1 -timeout 60s 2>&1 | grep "FAIL\|Error\|panic" | head -20 || true)
  fi

  # Ask Claude to plan
  cd "$REPO_DIR"
  claude -p --model "$CLAUDE_MODEL" --dangerously-skip-permissions \
    "You are a Senior Technical Project Manager. Analyze this project and plan the next $AUTO_PHASES development phases.

PROJECT CONTEXT (CLAUDE.md):
$project_context

CURRENT STATE:
- Go source files: $go_files
- Test files: $test_files
- Frontend files: $tsx_files
- TODO/FIXME count: $todo_count
- Builds: $build_ok
- Tests: $test_ok
$([ -n "$compile_errors" ] && echo "- Compile errors: $compile_errors")
$([ -n "$test_failures" ] && echo "- Test failures: $test_failures")

COMPLETED ROUNDS:
$history

RULES:
1. If build is broken, Phase 1 MUST fix compilation
2. If tests fail, prioritize fixing tests early
3. Each phase must be a single clear task for team.sh --project
4. Phases should build on each other (dependencies first)
5. Include a mix of: bug fixes, new features, testing, hardening
6. Each description must be detailed enough for an AI dev team to implement (50-150 words)
7. DO NOT repeat already completed rounds

Respond with ONLY JSON:
{
  \"phases\": [
    {
      \"order\": 1,
      \"name\": \"Short name\",
      \"priority\": \"critical|high|medium\",
      \"category\": \"fix|feature|test|security|performance|devops\",
      \"description\": \"Detailed description for team.sh --project\",
      \"success_criteria\": [\"go build passes\", \"specific test passes\"],
      \"estimated_minutes\": 90
    }
  ],
  \"project_health\": {
    \"score\": 75,
    \"critical_issues\": [\"issue\"],
    \"strengths\": [\"strength\"]
  },
  \"rationale\": \"Why these phases in this order\"
}" \
    > "$PLAN_FILE" 2>/dev/null || true

  # Extract JSON
  python3 - "$PLAN_FILE" << 'PYEOF'
import json, re, sys
f = sys.argv[1]
content = open(f).read()
m = re.search(r'\{[\s\S]*\}', content)
if m:
    try:
        parsed = json.loads(m.group())
        json.dump(parsed, open(f, "w"), indent=2)
    except: pass
PYEOF

  # Display plan
  slog "📋 Next phases planned:"
  python3 - "$PLAN_FILE" << 'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    health = d.get("project_health", {})
    print(f"  Project health: {health.get('score', '?')}/100")
    for issue in health.get("critical_issues", []):
        print(f"  ⚠ {issue}")
    print()
    for p in d.get("phases", []):
        icon = {"fix":"🔧","feature":"✨","test":"🧪","security":"🔒","performance":"⚡","devops":"🐳"}.get(p.get("category",""), "📌")
        print(f"  {p['order']}. {icon} [{p.get('priority','?')}] {p['name']}")
        print(f"     {p['description'][:80]}...")
        print(f"     ⏱ ~{p.get('estimated_minutes', '?')}min")
        print()
    print(f"  Rationale: {d.get('rationale', 'N/A')}")
except Exception as e:
    print(f"  Error reading plan: {e}")
PYEOF
}

execute_planned_phases() {
  slog "🚀 Executing planned phases..."

  init_phase_history

  if [ ! -f "$PLAN_FILE" ]; then
    plan_next_phases
  fi

  local total
  total=$(python3 -c "import json; print(len(json.load(open('$PLAN_FILE')).get('phases',[])))" 2>/dev/null || echo "0")

  if [ "$total" -eq 0 ]; then
    serr "No phases planned. Run: ./supervisor.sh plan"
    return 1
  fi

  local i=0
  while [ "$i" -lt "$total" ]; do
    local phase_data
    phase_data=$(python3 -c "
import json
d = json.load(open('$PLAN_FILE'))
p = d['phases'][$i]
print(p['description'])
" 2>/dev/null || echo "")

    local phase_name
    phase_name=$(python3 -c "
import json
d = json.load(open('$PLAN_FILE'))
print(d['phases'][$i].get('name','Phase $((i+1))'))
" 2>/dev/null || echo "Phase $((i+1))")

    if [ -z "$phase_data" ]; then
      swarn "Empty phase $((i+1)) — skipping"
      i=$((i+1)); continue
    fi

    slog "╔═══════════════════════════════════════╗"
    slog "║  ROUND $((i+1))/$total: $phase_name"
    slog "╚═══════════════════════════════════════╝"

    # Reset team state for new round
    if [ -f "$STATE_FILE" ]; then
      python3 - "$STATE_FILE" "$phase_data" << 'PYEOF'
import json, sys
f = sys.argv[1]
d = {"phases": {}, "project": sys.argv[2], "branch": ""}
json.dump(d, open(f, "w"), indent=2)
PYEOF
    fi

    # Run team.sh for this phase
    team_start "$phase_data"

    # Monitor until complete or crash
    local phase_crashes=0
    local phase_done=false

    while [ "$phase_done" = false ]; do
      sleep "$HEALTH_INTERVAL"

      if ! team_is_running; then
        local deploy_st; deploy_st=$(phase_status deploy)
        if [ "$deploy_st" = "done" ]; then
          slog "✅ Round $((i+1)) complete: $phase_name"
          record_completed_round "$phase_name: $phase_data"
          phase_done=true
          continue
        fi

        # Check if all code phases done (sometimes deploy is skipped)
        local sec_st; sec_st=$(phase_status security)
        if [ "$sec_st" = "done" ]; then
          slog "✅ Round $((i+1)) complete (no deploy): $phase_name"
          record_completed_round "$phase_name: $phase_data"
          phase_done=true
          continue
        fi

        phase_crashes=$((phase_crashes + 1))
        serr "💥 Crash in round $((i+1)) (crash #$phase_crashes)"

        if [ "$phase_crashes" -ge 3 ]; then
          swarn "Too many crashes in round $((i+1)) — skipping"
          record_completed_round "SKIPPED: $phase_name"
          phase_done=true
          continue
        fi

        # Self-heal
        local cur; cur=$(current_phase)
        if check_terminated; then
          heal_terminated
        elif check_error_pattern; then
          heal_error
        else
          sleep 10
          team_resume || skip_phase "$cur"
        fi
      else
        # Running — check health
        if ! check_phase_timeout; then
          heal_stuck
        fi
      fi
    done

    i=$((i+1))
    sleep 5
  done

  slog ""
  slog "╔═══════════════════════════════════════╗"
  slog "║  🎉 ALL $total ROUNDS COMPLETE          ║"
  slog "╚═══════════════════════════════════════╝"

  # Plan next batch?
  slog "Planning next batch..."
  plan_next_phases
}

improve_project() {
  slog "🚀 Running improvement cycle..."
  plan_next_phases
  execute_planned_phases
}

# ═══════════════════════════════════
# WATCH LOOP (MAIN SUPERVISOR)
# ═══════════════════════════════════

watch_loop() {
  local crash_count=0

  slog "╔═══════════════════════════════════════╗"
  slog "║  🛡️  SUPERVISOR ACTIVE                 ║"
  slog "╚═══════════════════════════════════════╝"
  slog "Monitoring: $REPO_DIR"
  slog "Health check: every ${HEALTH_INTERVAL}s"
  slog "PID: $$"

  echo $$ > "$SUP_PID"
  trap 'rm -f "$SUP_PID"; slog "Supervisor stopped"; exit 0' EXIT INT TERM

  while true; do
    sleep "$HEALTH_INTERVAL"

    # Is team.sh still running?
    if ! team_is_running; then
      # Check if it completed successfully
      local deploy_status; deploy_status=$(phase_status deploy)
      if [ "$deploy_status" = "done" ]; then
        slog "🎉 Initial build complete! All phases done."
        record_completed_round "$(get_state _meta project)"
        slog "Planning and executing next $AUTO_PHASES improvement phases..."
        plan_next_phases
        execute_planned_phases
        break
      fi

      # It crashed
      crash_count=$((crash_count + 1))
      local phase; phase=$(current_phase)
      serr "💥 team.sh crashed! (crash #$crash_count, phase: $phase)"

      if [ "$crash_count" -ge "$MAX_CRASHES" ]; then
        serr "Too many crashes ($crash_count). Giving up."
        serr "Last phase: $phase"
        serr "Run manually: ./supervisor.sh skip $phase"
        break
      fi

      # Check what killed it
      if check_terminated; then
        heal_terminated
      elif check_error_pattern; then
        heal_error
      else
        # Unknown crash — just resume
        slog "Unknown crash — attempting resume"
        sleep 10
        team_resume || {
          swarn "Resume failed — trying with phase skip"
          skip_phase "$(current_phase)"
        }
      fi
      continue
    fi

    # team.sh is running — check health
    if ! check_phase_timeout; then
      heal_stuck
      crash_count=0
      continue
    fi

    if ! check_live_log_stale; then
      swarn "Live log stale — checking process"
      if team_is_running; then
        slog "  Process alive but quiet — waiting"
      else
        serr "  Process dead — restarting"
        team_resume
      fi
      continue
    fi

    # All healthy
    crash_count=0
  done
}

# ═══════════════════════════════════
# STATUS DASHBOARD
# ═══════════════════════════════════

show_status() {
  echo ""
  echo -e "  ${W}═══ SUPERVISOR DASHBOARD ═══${NC}"
  echo ""

  # Supervisor status
  if [ -f "$SUP_PID" ] && kill -0 "$(cat "$SUP_PID" 2>/dev/null)" 2>/dev/null; then
    echo -e "  🛡️  Supervisor: ${G}ACTIVE${NC} (PID: $(cat "$SUP_PID"))"
  else
    echo -e "  🛡️  Supervisor: ${R}STOPPED${NC}"
  fi

  # Team status
  if team_is_running; then
    echo -e "  🤖 Team:       ${G}RUNNING${NC} (PID: $(cat "$TEAM_DIR/team.pid" 2>/dev/null))"
  else
    echo -e "  🤖 Team:       ${R}STOPPED${NC}"
  fi

  echo ""

  # Phase progress
  if [ -f "$STATE_FILE" ]; then
    python3 - "$STATE_FILE" << 'PYEOF'
import json, sys
from datetime import datetime

d = json.load(open(sys.argv[1]))
print(f"  Project: {d.get('project','')[:60]}")
print(f"  Branch:  {d.get('branch','')}")
print()

phases = ["requirements","market_research","design","backend","frontend","testing","qa","security","deploy"]
icons = {"done":"✅","running":"🔄","pending":"⬜","failed":"❌","skipped":"⏭️"}
roles = {"requirements":"PM","market_research":"Research","design":"Architect","backend":"Backend","frontend":"Frontend","testing":"Tester","qa":"QA","security":"Security","deploy":"DevOps"}

done = 0
for p in phases:
    data = d.get("phases",{}).get(p,{})
    st = data.get("status","pending")
    if st == "done": done += 1
    retries = data.get("_retries","")
    retry_str = f" (retries: {retries})" if retries else ""
    verdict = data.get("verdict","")
    verdict_str = f" → {verdict}" if verdict else ""
    updated = data.get("_updated","")
    time_str = f" [{updated[11:19]}]" if updated else ""

    print(f"  {icons.get(st,'⬜')} {roles.get(p,p):10s}{verdict_str}{retry_str}{time_str}")

    for k,v in sorted(data.items()):
        if k.startswith("_") or k in ("status","verdict"): continue
        print(f"     └─ {k}: {v}")

print(f"\n  Progress: {done}/{len(phases)} phases ({done*100//len(phases)}%)")
PYEOF
  fi

  # Recent supervisor actions
  echo ""
  echo -e "  ${B}Recent supervisor actions:${NC}"
  tail -5 "$SUP_LOG" 2>/dev/null | while read -r line; do echo "    $line"; done

  # Patches applied
  local patch_count
  patch_count=$(ls "$PATCHES_DIR"/*.patch 2>/dev/null | wc -l || echo "0")
  if [ "$patch_count" -gt 0 ]; then
    echo ""
    echo -e "  ${M}Patches applied: $patch_count${NC}"
    ls -1t "$PATCHES_DIR"/*.patch 2>/dev/null | head -3 | while read -r f; do
      echo "    $(basename "$f")"
    done
  fi

  # Completed rounds
  if [ -f "$PHASE_HISTORY" ]; then
    local round_count
    round_count=$(python3 -c "import json; print(len(json.load(open('$PHASE_HISTORY')).get('completed',[])))" 2>/dev/null || echo "0")
    if [ "$round_count" -gt 0 ]; then
      echo ""
      echo -e "  ${G}Completed rounds: $round_count${NC}"
      python3 -c "
import json
d = json.load(open('$PHASE_HISTORY'))
for r in d.get('completed',[])[-3:]:
    print(f\"    ✅ {r.get('description','')[:70]}\")" 2>/dev/null || true
    fi
  fi

  # Planned phases
  if [ -f "$PLAN_FILE" ]; then
    echo ""
    echo -e "  ${B}Planned next phases:${NC}"
    python3 -c "
import json
d = json.load(open('$PLAN_FILE'))
for p in d.get('phases',[]):
    icon = {'fix':'🔧','feature':'✨','test':'🧪','security':'🔒','performance':'⚡','devops':'🐳'}.get(p.get('category',''),'📌')
    print(f\"    {p['order']}. {icon} [{p.get('priority','?')}] {p['name']}\")" 2>/dev/null || true
  fi

  echo ""
}

# ═══════════════════════════════════
# CLI
# ═══════════════════════════════════

show_help() {
  cat << 'HELP'

  ╔══════════════════════════════════════════╗
  ║  🛡️  SUPERVISOR — Self-Healing Controller ║
  ╚══════════════════════════════════════════╝

  CONTROL:
    ./supervisor.sh start "project desc"   # Start team + supervisor
    ./supervisor.sh watch                  # Supervisor only (team already running)
    ./supervisor.sh restart                # Stop + resume team
    ./supervisor.sh stop                   # Stop everything
    ./supervisor.sh skip [phase]           # Skip stuck phase

  PLANNING:
    ./supervisor.sh plan [N]               # Plan next N phases (default: 3)
    ./supervisor.sh execute [N]            # Execute planned phases
    ./supervisor.sh next [N]               # Plan + execute in one shot
    ./supervisor.sh history                # Show completed rounds

  HEALING:
    ./supervisor.sh patch "description"    # Auto-fix team.sh with Claude
    ./supervisor.sh improve [N]            # Analyze + plan + execute N phases
    ./supervisor.sh status                 # Dashboard
    ./supervisor.sh logs                   # Show supervisor log

  AUTO-PILOT:
    After initial build completes, supervisor auto-plans and executes
    3 improvement phases (fix bugs, add features, harden).
    Set AUTO_PHASES=5 for more phases.

  EXAMPLE:
    ./supervisor.sh start "Build PAM platform..."
    # ... initial 9-phase build runs ...
    # ... supervisor auto-plans 3 improvement rounds ...
    # ... each round runs full team.sh waterfall ...
    # ... self-heals crashes, skips stuck phases ...

    # Want more?
    ./supervisor.sh next 5    # Plan + execute 5 more rounds

HELP
}

case "${1:-}" in
  start)
    [ -z "${2:-}" ] && { serr "Usage: ./supervisor.sh start \"project description\" [num_phases]"; exit 1; }
    AUTO_PHASES="${3:-3}"
    export AUTO_PHASES
    team_start "$2"
    nohup bash "$0" watch >> "$SUP_LOG" 2>&1 &
    echo ""
    echo "  ✅ Supervisor + Team started"
    echo "  📺 tail -f $LIVE_LOG"
    echo "  📊 ./supervisor.sh status"
    echo "  🛑 ./supervisor.sh stop"
    echo "  🔄 After build: auto-plans $AUTO_PHASES improvement rounds"
    echo ""
    ;;

  watch)
    watch_loop
    ;;

  status)
    show_status
    ;;

  skip)
    skip_phase "${2:-}"
    ;;

  restart)
    team_stop
    sleep 3
    team_resume
    ;;

  stop)
    team_stop
    if [ -f "$SUP_PID" ]; then
      kill "$(cat "$SUP_PID")" 2>/dev/null || true
      rm -f "$SUP_PID"
    fi
    slog "✓ Everything stopped"
    ;;

  patch)
    [ -z "${2:-}" ] && { serr "Usage: ./supervisor.sh patch \"problem description\""; exit 1; }
    patch_team_with_claude "$2"
    ;;

  plan)
    AUTO_PHASES="${2:-3}"
    plan_next_phases
    ;;

  execute|run)
    AUTO_PHASES="${2:-3}"
    execute_planned_phases
    ;;

  next)
    AUTO_PHASES="${2:-3}"
    plan_next_phases
    execute_planned_phases
    ;;

  improve)
    AUTO_PHASES="${2:-3}"
    improve_project
    ;;

  history)
    if [ -f "$PHASE_HISTORY" ]; then
      python3 -c "
import json
d = json.load(open('$PHASE_HISTORY'))
print(f'Completed rounds: {len(d.get(\"completed\",[]))}')
print()
for i, r in enumerate(d.get('completed',[]), 1):
    print(f'  {i}. [{r.get(\"timestamp\",\"\")[:19]}] {r.get(\"description\",\"\")[:80]}')
"
    else
      echo "No history yet"
    fi
    ;;

  logs)
    tail -50 "$SUP_LOG"
    ;;

  -h|--help|help)
    show_help
    ;;

  *)
    show_help
    ;;
esac
