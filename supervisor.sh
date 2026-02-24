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
ARTIFACTS="$TEAM_DIR/artifacts"

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

mkdir -p "$TEAM_DIR" "$PATCHES_DIR" "$ARTIFACTS" "$TEAM_DIR/logs"
touch "$SUP_LOG" "$LIVE_LOG"

slog() { echo -e "${G}[SUP $(date '+%H:%M:%S')]${NC} $1" | tee -a "$SUP_LOG"; }
swarn() { echo -e "${Y}[SUP $(date '+%H:%M:%S')]${NC} $1" | tee -a "$SUP_LOG"; }
serr() { echo -e "${R}[SUP $(date '+%H:%M:%S')]${NC} $1" | tee -a "$SUP_LOG"; }

# Safe Claude wrapper — timeout + stdin closed + killable
# Usage: run_claude TIMEOUT_SECS OUTPUT_FILE "prompt"
run_claude() {
  local max_secs="${1:-300}" out_file="${2:-/dev/null}" prompt="$3"
  
  claude -p --model "$CLAUDE_MODEL" --dangerously-skip-permissions \
    "$prompt" </dev/null > "$out_file" 2>&1 &
  local cpid=$!
  
  local waited=0
  while kill -0 "$cpid" 2>/dev/null && [ "$waited" -lt "$max_secs" ]; do
    sleep 5; waited=$((waited + 5))
  done
  
  if kill -0 "$cpid" 2>/dev/null; then
    slog "  ⏰ Claude timed out (${max_secs}s) — killing"
    kill "$cpid" 2>/dev/null; sleep 2; kill -9 "$cpid" 2>/dev/null || true
    wait "$cpid" 2>/dev/null || true
    return 124
  fi
  
  wait "$cpid" 2>/dev/null
  return $?
}

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
  # setsid = new session (no controlling tty), </dev/null = don't block stdin
  setsid bash "$TEAM_SH" --project "$project" </dev/null >> "$LIVE_LOG" 2>&1 &
  disown
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
  setsid bash "$TEAM_SH" --resume </dev/null >> "$LIVE_LOG" 2>&1 &
  disown
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

  local _prompt="Read the file team.sh in the current directory.

PROBLEM: $problem

Fix the bug in team.sh. The script uses 'set -euo pipefail' so any pipe returning non-zero kills the script.
Common fixes:
- Add '|| true' to grep/find pipes that might return empty
- Use variable=\$(cmd || true) pattern
- Don't use PIPESTATUS with pipefail
- Add '|| rc=\$?' pattern for commands that might fail

Make MINIMAL changes. Only fix the specific bug. Test with 'bash -n team.sh'."

  run_claude 300 "$fix_log" "$_prompt"

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
  local desc="$1" category="${2:-project}" result="${3:-done}"
  python3 - "$PHASE_HISTORY" "$desc" "$category" "$result" << 'PYEOF'
import json, sys, os
from datetime import datetime
f, desc, cat, res = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
d = json.load(open(f)) if os.path.exists(f) else {"completed":[],"current_round":0}
d["completed"].append({"description": desc, "category": cat, "result": res, "timestamp": datetime.now().isoformat()})
d["current_round"] = len(d["completed"])
json.dump(d, open(f, "w"), indent=2)
PYEOF
}

# ═══════════════════════════════════
# STEP 1: DIAGNOSE — Analyze Everything
# ═══════════════════════════════════

diagnose_project() {
  slog "🔍 STEP 1: DIAGNOSING project + process..."

  cd "$REPO_DIR"
  local report="$ARTIFACTS/diagnosis.json"

  # Gather project health (strip whitespace from all counts)
  local go_files; go_files=$(find "$REPO_DIR/internal" "$REPO_DIR/cmd" -name "*.go" 2>/dev/null | wc -l || true)
  go_files="${go_files//[^0-9]/}"; go_files="${go_files:-0}"
  local test_files; test_files=$(find "$REPO_DIR" -name "*_test.go" 2>/dev/null | wc -l || true)
  test_files="${test_files//[^0-9]/}"; test_files="${test_files:-0}"
  local tsx_files; tsx_files=$(find "$REPO_DIR/frontend/src" -name "*.tsx" -o -name "*.ts" 2>/dev/null | wc -l || true)
  tsx_files="${tsx_files//[^0-9]/}"; tsx_files="${tsx_files:-0}"
  local todo_count; todo_count=$(grep -rn "TODO\|FIXME\|HACK\|XXX" "$REPO_DIR/internal" "$REPO_DIR/cmd" "$REPO_DIR/frontend/src" 2>/dev/null | wc -l || true)
  todo_count="${todo_count//[^0-9]/}"; todo_count="${todo_count:-0}"
  local todo_list; todo_list=$(grep -rn "TODO\|FIXME\|HACK\|XXX" "$REPO_DIR/internal" "$REPO_DIR/cmd" "$REPO_DIR/frontend/src" 2>/dev/null | head -20 || true)

  # Build check
  local build_ok="yes" compile_errors=""
  go build ./... 2>/dev/null || { build_ok="no"; compile_errors=$(go build ./... 2>&1 | tail -20 || true); }

  # Test check
  local test_ok="pass" test_failures="" test_count=0 test_passed=0
  local test_output; test_output=$(go test ./... -count=1 -timeout 120s 2>&1 || true)
  echo "$test_output" | grep -q "^FAIL" && test_ok="fail"
  test_count=$(echo "$test_output" | grep -c "^---\|^ok\|^FAIL" || true)
  test_count="${test_count//[^0-9]/}"; test_count="${test_count:-0}"
  test_passed=$(echo "$test_output" | grep -c "^ok " || true)
  test_passed="${test_passed//[^0-9]/}"; test_passed="${test_passed:-0}"
  test_failures=$(echo "$test_output" | grep -A 2 "FAIL\|Error\|panic" | head -20 || true)

  # Docker check
  local dockerfiles; dockerfiles=$(find deployments/docker -maxdepth 1 -name "Dockerfile.*" 2>/dev/null | wc -l || true)
  dockerfiles="${dockerfiles//[^0-9]/}"; dockerfiles="${dockerfiles:-0}"
  local compose_exists="no"
  [ -f "deployments/docker/docker-compose.yml" ] || [ -f "docker-compose.yml" ] && compose_exists="yes"

  # Frontend check
  local frontend_exists="no" ts_errors=""
  if [ -d "$REPO_DIR/frontend" ]; then
    frontend_exists="yes"
    cd "$REPO_DIR/frontend"
    [ -d node_modules ] || npm install 2>/dev/null || true
    if [ -f node_modules/.bin/tsc ]; then
      ts_errors=$(npx tsc --noEmit 2>&1 | grep "error TS" | head -10 || true)
    fi
    cd "$REPO_DIR"
  fi

  # Error history from team.sh
  local error_patterns=""
  if [ -f "$TEAM_DIR/error_history.jsonl" ]; then
    error_patterns=$(python3 -c "
import json
from collections import Counter
errors = []
for line in open('$TEAM_DIR/error_history.jsonl'):
    try: errors.append(json.loads(line.strip()))
    except: pass
types = Counter(e.get('type','') for e in errors)
for t, c in types.most_common(5):
    print(f'  {t}: {c} occurrences')
" 2>/dev/null || echo "  No errors recorded")
  fi

  # team.sh process analysis
  local process_issues=""
  if [ -f "$LIVE_LOG" ]; then
    local terminated_count; terminated_count=$(grep -c "Terminated" "$LIVE_LOG" 2>/dev/null || true)
    terminated_count="${terminated_count//[^0-9]/}"; terminated_count="${terminated_count:-0}"
    local retry_count; retry_count=$(grep -c "Attempt [23]/3" "$LIVE_LOG" 2>/dev/null || true)
    retry_count="${retry_count//[^0-9]/}"; retry_count="${retry_count:-0}"
    local stuck_count; stuck_count=$(grep -c "stuck\|stale\|timeout" "$SUP_LOG" 2>/dev/null || true)
    stuck_count="${stuck_count//[^0-9]/}"; stuck_count="${stuck_count:-0}"
    process_issues="Terminated: $terminated_count, Retries: $retry_count, Stuck: $stuck_count"
  fi

  # Completed rounds
  local history
  history=$(cat "$PHASE_HISTORY" 2>/dev/null || echo '{"completed":[]}')

  # Write diagnosis safely (avoid heredoc with bash-expanded content)
  local _tmpdiag="$TEAM_DIR/tmp_diag_data.json"
  # Write raw text fields to temp files to avoid quote/escape issues
  echo "$compile_errors" > "$TEAM_DIR/tmp_ce.txt" 2>/dev/null
  echo "$test_failures" > "$TEAM_DIR/tmp_tf.txt" 2>/dev/null
  echo "$ts_errors" > "$TEAM_DIR/tmp_ts.txt" 2>/dev/null
  echo "$todo_list" > "$TEAM_DIR/tmp_td.txt" 2>/dev/null
  echo "$error_patterns" > "$TEAM_DIR/tmp_ep.txt" 2>/dev/null

  python3 -c '
import json, sys, os
d = sys.argv
report = {
    "project": {
        "go_files": int(d[1]),
        "test_files": int(d[2]),
        "tsx_files": int(d[3]),
        "todo_count": int(d[4]),
        "build": d[5],
        "tests": d[6],
        "test_count": int(d[7]),
        "test_passed": int(d[8]),
        "dockerfiles": int(d[9]),
        "compose": d[10],
        "frontend": d[11]
    },
    "compile_errors": open(d[12]).read().strip() if os.path.exists(d[12]) else "",
    "test_failures": open(d[13]).read().strip() if os.path.exists(d[13]) else "",
    "ts_errors": open(d[14]).read().strip() if os.path.exists(d[14]) else "",
    "todos": open(d[15]).read().strip() if os.path.exists(d[15]) else "",
    "error_patterns": open(d[16]).read().strip() if os.path.exists(d[16]) else "",
    "process_issues": d[17]
}
try:
    report["history"] = json.loads(d[18])
except:
    report["history"] = {"completed": []}
json.dump(report, open(d[19], "w"), indent=2)
' "$go_files" "$test_files" "$tsx_files" "$todo_count" \
  "$build_ok" "$test_ok" "$test_count" "$test_passed" \
  "$dockerfiles" "$compose_exists" "$frontend_exists" \
  "$TEAM_DIR/tmp_ce.txt" "$TEAM_DIR/tmp_tf.txt" "$TEAM_DIR/tmp_ts.txt" \
  "$TEAM_DIR/tmp_td.txt" "$TEAM_DIR/tmp_ep.txt" \
  "$process_issues" "$history" "$report" \
  2>/dev/null || slog "  ⚠ Diagnosis write failed"

  rm -f "$TEAM_DIR"/tmp_ce.txt "$TEAM_DIR"/tmp_tf.txt "$TEAM_DIR"/tmp_ts.txt \
        "$TEAM_DIR"/tmp_td.txt "$TEAM_DIR"/tmp_ep.txt

  # Display diagnosis
  slog "📊 DIAGNOSIS:"
  slog "  Code:    $go_files .go + $tsx_files .ts/tsx + $test_files tests"
  slog "  Build:   $build_ok | Tests: $test_ok ($test_passed/$test_count)"
  slog "  TODOs:   $todo_count | Docker: $dockerfiles files"
  slog "  Process: $process_issues"
  [ -n "$compile_errors" ] && slog "  ⚠ Compile errors found"
  [ -n "$test_failures" ] && slog "  ⚠ Test failures found"
  [ -n "$ts_errors" ] && slog "  ⚠ TypeScript errors found"
}

# ═══════════════════════════════════════════════════
# TRACK A: IMPROVE TEAM.SH (Process/Workflow)
# ═══════════════════════════════════════════════════

TEAM_PLAN_FILE="$TEAM_DIR/artifacts/team_improvements.json"
TEAM_ANALYSIS_FILE="$TEAM_DIR/artifacts/team_analysis.json"

# ── A1: Analyze team.sh structure ──
analyze_team() {
  slog "🔬 A1: ANALYZING team.sh..."

  local team_lines; team_lines=$(wc -l < "$TEAM_SH" || true)
  team_lines="${team_lines//[^0-9]/}"; team_lines="${team_lines:-0}"
  local func_count; func_count=$(grep -c "^[a-z_]*() {" "$TEAM_SH" || true)
  func_count="${func_count//[^0-9]/}"; func_count="${func_count:-0}"
  local func_list; func_list=$(grep "^[a-z_]*() {" "$TEAM_SH" | sed 's/() {.*//' | tr '\n' ',' | sed 's/,$//')

  # Prompt sizes per phase
  local prompt_analysis
  cat > "$TEAM_DIR/tmp_analyze.py" << 'PYEOF'
import re, sys, json
content = open(sys.argv[1]).read()
prompts = []
for m in re.finditer(r'^(phase_\w+)\(\)', content, re.MULTILINE):
    name = m.group(1)
    start = m.start()
    next_phase = content.find('\nphase_', start + 1)
    if next_phase == -1: next_phase = len(content)
    block = content[start:next_phase]
    pipe_count = block.count('| ')
    pipe_safe = block.count('|| true') + block.count('|| echo') + block.count('|| rc=')
    prompts.append({
        "phase": name,
        "lines": block.count('\n'),
        "claude_calls": block.count('claude_do'),
        "pipes": pipe_count,
        "safe_pipes": pipe_safe,
        "unsafe_pipes": max(0, pipe_count - pipe_safe - block.count('| tee') - block.count('| tail') - block.count('| head'))
    })
print(json.dumps(prompts, indent=2))
PYEOF
  prompt_analysis=$(python3 "$TEAM_DIR/tmp_analyze.py" "$TEAM_SH" 2>/dev/null || echo "[]")
  rm -f "$TEAM_DIR/tmp_analyze.py"

  # Error handling quality
  local pipefail_safe; pipefail_safe=$(grep -c "|| true\||| echo\||| rc=\||| build_" "$TEAM_SH" || true)
  pipefail_safe="${pipefail_safe//[^0-9]/}"; pipefail_safe="${pipefail_safe:-0}"
  local raw_pipes; raw_pipes=$(grep -c "| grep\|| awk\|| sed\|| cut\|| wc" "$TEAM_SH" || true)
  raw_pipes="${raw_pipes//[^0-9]/}"; raw_pipes="${raw_pipes:-0}"
  local has_set_e; has_set_e=$(grep -c "set -e\|set -o errexit\|set -o pipefail" "$TEAM_SH" || true)
  has_set_e="${has_set_e//[^0-9]/}"; has_set_e="${has_set_e:-0}"

  # Timeout check
  local timeout_calls; timeout_calls=$(grep -c "timeout " "$TEAM_SH" || true)
  timeout_calls="${timeout_calls//[^0-9]/}"; timeout_calls="${timeout_calls:-0}"

  # Hardcoded values
  local hardcoded; hardcoded=$(grep -n "localhost\|127\.0\.0\.1\|:8080\|:3000\|:5432" "$TEAM_SH" | grep -v "^#" | head -10 || true)

  # Error history
  local error_summary=""
  if [ -f "$TEAM_DIR/error_history.jsonl" ]; then
    error_summary=$(python3 -c "
import json
from collections import Counter
errors = []
for line in open('$TEAM_DIR/error_history.jsonl'):
    try: errors.append(json.loads(line.strip()))
    except: pass
by_phase = Counter(e.get('phase','?') for e in errors)
by_type = Counter(e.get('type','?') for e in errors)
print('By phase: ' + ', '.join(f'{k}:{v}' for k,v in by_phase.most_common(5)))
print('By type:  ' + ', '.join(f'{k}:{v}' for k,v in by_type.most_common(5)))
print(f'Total: {len(errors)} errors')
" 2>/dev/null || echo "No errors")
  fi

  # Process crash history from logs
  local terminated_count=0 retry_count=0 stuck_count=0
  if [ -f "$LIVE_LOG" ]; then
    terminated_count=$(grep -c "Terminated" "$LIVE_LOG" 2>/dev/null || true)
    terminated_count="${terminated_count//[^0-9]/}"; terminated_count="${terminated_count:-0}"
    retry_count=$(grep -c "Attempt [23]/3" "$LIVE_LOG" 2>/dev/null || true)
    retry_count="${retry_count//[^0-9]/}"; retry_count="${retry_count:-0}"
    stuck_count=$(grep -c "stuck\|stale\|timeout\|Timeout" "$SUP_LOG" 2>/dev/null || true)
    stuck_count="${stuck_count//[^0-9]/}"; stuck_count="${stuck_count:-0}"
  fi

  # Write analysis safely (no heredoc interpolation — pass values as args)
  python3 -c '
import json, sys
analysis = {
    "structure": {
        "total_lines": int(sys.argv[1]),
        "function_count": int(sys.argv[2]),
        "functions": sys.argv[3],
        "pipefail_safe_pipes": int(sys.argv[4]),
        "raw_pipes": int(sys.argv[5]),
        "has_strict_mode": int(sys.argv[6]),
        "timeout_calls": int(sys.argv[7])
    },
    "phases": json.loads(sys.argv[8]) if sys.argv[8].strip().startswith("[") else [],
    "hardcoded_values": sys.argv[9],
    "error_history": sys.argv[10],
    "process_crashes": {
        "terminated": int(sys.argv[11]),
        "retries": int(sys.argv[12]),
        "stuck": int(sys.argv[13])
    }
}
json.dump(analysis, open(sys.argv[14], "w"), indent=2)
' "$team_lines" "$func_count" "$func_list" "$pipefail_safe" "$raw_pipes" \
  "$has_set_e" "$timeout_calls" "$prompt_analysis" \
  "${hardcoded:-none}" "${error_summary:-none}" \
  "$terminated_count" "$retry_count" "$stuck_count" \
  "$TEAM_ANALYSIS_FILE" 2>/dev/null || slog "  ⚠ Analysis write failed"

  # Display
  slog "📊 TEAM.SH ANALYSIS:"
  slog "  Lines: $team_lines | Functions: $func_count"
  slog "  Pipes: $raw_pipes raw, $pipefail_safe safe | Timeouts: $timeout_calls"
  slog "  Crashes: Terminated=$terminated_count Retries=$retry_count Stuck=$stuck_count"
  [ -n "$error_summary" ] && slog "  Errors: $error_summary"
  [ -n "$hardcoded" ] && slog "  ⚠ Hardcoded values found"

  # Score
  local team_score=100
  [ "$terminated_count" -gt 5 ] && team_score=$((team_score - 20))
  [ "$retry_count" -gt 10 ] && team_score=$((team_score - 15))
  [ "$stuck_count" -gt 3 ] && team_score=$((team_score - 15))
  [ "$raw_pipes" -gt 20 ] && team_score=$((team_score - 10))
  [ "$timeout_calls" -lt 3 ] && team_score=$((team_score - 10))
  slog "  🏆 Process Score: $team_score/100"
}

# ── A2: Plan team.sh improvements ──
plan_team_improvements() {
  local num_steps="${1:-3}"
  slog "🧠 A2: PLANNING $num_steps team.sh improvements..."

  local analysis; analysis=$(cat "$TEAM_ANALYSIS_FILE" 2>/dev/null || echo "{}")
  local team_head; team_head=$(head -c 4000 "$TEAM_SH" 2>/dev/null)
  local history; history=$(cat "$PHASE_HISTORY" 2>/dev/null || echo "{}")

  cd "$REPO_DIR"
  local completed_rounds
  completed_rounds=$(python3 -c "
import json
d = json.loads('''$history''')
for r in d.get('completed',[]):
    if r.get('category') == 'team': print(f\"  - [{r.get('result','')}] {r.get('description','')[:80]}\")
" 2>/dev/null || echo "  None")

  local _prompt="You are a DevOps Process Engineer. Analyze team.sh (an AI dev team orchestrator) and plan $num_steps improvements.

TEAM.SH ANALYSIS:
$analysis

TEAM.SH HEADER (first 4000 chars):
$team_head

COMPLETED ROUNDS:
$completed_rounds

WHAT TO IMPROVE — PRIORITY ORDER:
1. CRASH FIXES: If Terminated/Stuck counts are high, fix the root causes (prompt too big, missing || true, no timeout)
2. PIPELINE SAFETY: Add || true to unsafe grep/find/awk pipes that kill pipefail scripts
3. PROMPT OPTIMIZATION: Shrink prompts >8000 chars, use summarize_artifact(), extract only failures
4. SMART RETRIES: Add exponential backoff, reduce attempts for known-fatal errors (OOM)
5. NEW PHASES: Add missing phases like api-testing, documentation, load-testing, monitoring
6. PHASE SKIP LOGIC: Allow skipping phases based on project type (no frontend = skip frontend phase)
7. PROCESS METRICS: Add timing per phase, success rates, cost tracking
8. PROMPT QUALITY: Make prompts more specific with file paths, function names, test commands

RULES:
- Each step is a SINGLE focused change to team.sh
- Each step must include: what to change, where (line/function), why, and verification command
- Steps must be independent (can apply in any order)
- DO NOT repeat already completed improvements
- Each change must keep team.sh valid bash (verify: bash -n team.sh)

RESPOND WITH ONLY JSON:
{
  \"steps\": [
    {
      \"order\": 1,
      \"name\": \"Short name\",
      \"category\": \"crash_fix|safety|prompt|retry|new_phase|skip_logic|metrics|quality\",
      \"priority\": \"critical|high|medium\",
      \"target_function\": \"function_name or line range\",
      \"description\": \"Exact change to make in team.sh. Be specific: which function, what code to add/change/remove.\",
      \"verification\": \"bash -n team.sh && echo OK\",
      \"risk\": \"low|medium|high\"
    }
  ],
  \"process_health\": {
    \"score\": 75,
    \"biggest_risk\": \"what causes most crashes\",
    \"biggest_win\": \"easiest improvement with highest impact\"
  }
}"

  local claude_rc=0
  run_claude 300 "$TEAM_PLAN_FILE" "$_prompt" || claude_rc=$?

  if [ "$claude_rc" -eq 124 ] || [ ! -s "$TEAM_PLAN_FILE" ]; then
    swarn "  ⚠ Team planning timed out or empty"
    echo '{"steps":[],"process_health":{"score":0}}' > "$TEAM_PLAN_FILE"
    return 0
  fi

  # Extract JSON
  python3 - "$TEAM_PLAN_FILE" << 'PYEOF'
import json, re, sys
f = sys.argv[1]
content = open(f).read()
m = re.search(r'\{[\s\S]*\}', content)
if m:
    try:
        parsed = json.loads(m.group())
        json.dump(parsed, open(f, "w"), indent=2)
    except: pass
else:
    json.dump({"steps":[]}, open(f, "w"), indent=2)
PYEOF

  # Display
  slog "📋 Team.sh improvement plan:"
  python3 - "$TEAM_PLAN_FILE" << 'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    h = d.get("process_health", {})
    print(f"  Process health: {h.get('score','?')}/100")
    print(f"  Biggest risk: {h.get('biggest_risk','?')}")
    print(f"  Biggest win:  {h.get('biggest_win','?')}")
    print()
    for s in d.get("steps", []):
        icon = {"crash_fix":"🔥","safety":"🛡️","prompt":"📝","retry":"🔄","new_phase":"✨","skip_logic":"⏭️","metrics":"📊","quality":"💎"}.get(s.get("category",""),"📌")
        print(f"  {s['order']}. {icon} [{s.get('priority','?')}] {s['name']}")
        print(f"     → {s.get('target_function','?')}")
        print(f"     {s['description'][:100]}...")
        print(f"     Risk: {s.get('risk','?')}")
        print()
except Exception as e:
    print(f"  Error: {e}")
PYEOF
}

# ── A3: Execute team.sh improvements step by step ──
execute_team_improvements() {
  slog "🚀 A3: EXECUTING team.sh improvements..."

  if [ ! -f "$TEAM_PLAN_FILE" ]; then
    serr "No team plan. Run: ./supervisor.sh plan-team"
    return 1
  fi

  local total
  total=$(python3 -c "import json; print(len(json.load(open('$TEAM_PLAN_FILE')).get('steps',[])))" 2>/dev/null || echo "0")

  if [ "$total" -eq 0 ]; then
    serr "No steps in team plan."
    return 1
  fi

  local applied=0 failed=0
  local i=0
  while [ "$i" -lt "$total" ]; do
    local step_name; step_name=$(python3 -c "
import json
d = json.load(open('$TEAM_PLAN_FILE'))
s = d['steps'][$i]
print(s.get('name', 'Step $((i+1))'))
" 2>/dev/null || echo "Step $((i+1))")

    local step_desc; step_desc=$(python3 -c "
import json
d = json.load(open('$TEAM_PLAN_FILE'))
s = d['steps'][$i]
print(s['description'])
" 2>/dev/null || echo "")

    local step_target; step_target=$(python3 -c "
import json
d = json.load(open('$TEAM_PLAN_FILE'))
s = d['steps'][$i]
print(s.get('target_function', 'team.sh'))
" 2>/dev/null || echo "team.sh")

    local step_verify; step_verify=$(python3 -c "
import json
d = json.load(open('$TEAM_PLAN_FILE'))
s = d['steps'][$i]
print(s.get('verification', 'bash -n team.sh'))
" 2>/dev/null || echo "bash -n team.sh")

    slog "┌───────────────────────────────────────┐"
    slog "│  Step $((i+1))/$total: $step_name"
    slog "│  Target: $step_target"
    slog "└───────────────────────────────────────┘"

    if [ -z "$step_desc" ]; then
      swarn "  Empty step — skipping"
      i=$((i+1)); continue
    fi

    # Backup before each step
    cp "$TEAM_SH" "$TEAM_SH.bak.step$((i+1)).$(date +%s)"

    # Apply with Claude
    cd "$REPO_DIR"
    local _prompt="Read team.sh. Make this ONE specific change:

CHANGE: $step_desc
TARGET: $step_target

RULES:
- Make ONLY this one change, nothing else
- Keep existing functionality intact
- Do NOT rewrite large sections
- Verify: $step_verify
- If the change is already applied, say 'ALREADY_DONE' and make no changes"

    run_claude 300 "$TEAM_DIR/logs/team_step_$((i+1)).log" "$_prompt"

    # Verify
    if bash -n "$TEAM_SH" 2>/dev/null; then
      slog "  ✓ Step $((i+1)) applied: $step_name"
      applied=$((applied + 1))
      record_completed_round "Team: $step_name — $step_desc" "team" "done"

      # Run custom verification if provided
      if [ -n "$step_verify" ] && [ "$step_verify" != "bash -n team.sh" ]; then
        cd "$REPO_DIR"
        if eval "$step_verify" 2>/dev/null; then
          slog "  ✓ Verification passed"
        else
          swarn "  ⚠ Verification failed (but syntax OK — keeping change)"
        fi
      fi
    else
      serr "  ✗ Step $((i+1)) broke team.sh — rolling back"
      local latest_bak; latest_bak=$(ls -t "$TEAM_SH".bak.step$((i+1)).* 2>/dev/null | head -1)
      [ -n "$latest_bak" ] && cp "$latest_bak" "$TEAM_SH"
      failed=$((failed + 1))
      record_completed_round "Team: FAILED $step_name" "team" "failed"
    fi

    i=$((i+1))
    sleep 2
  done

  slog ""
  slog "  Team.sh improvements: $applied applied, $failed failed out of $total"
}

# ── A4: Verify team.sh health ──
verify_team() {
  slog "✅ A4: VERIFYING team.sh..."

  local score=100

  # Syntax check
  if bash -n "$TEAM_SH" 2>/dev/null; then
    slog "  ✓ Syntax: PASS"
  else
    slog "  ✗ Syntax: FAIL"
    score=0
    return 1
  fi

  # Function count
  local funcs; funcs=$(grep -c "^[a-z_]*() {" "$TEAM_SH" || true)
  funcs="${funcs//[^0-9]/}"; funcs="${funcs:-0}"
  slog "  Functions: $funcs"
  [ "$funcs" -lt 15 ] && { slog "  ⚠ Low function count"; score=$((score - 10)); }

  # Required functions present
  local required="phase_requirements phase_design phase_backend phase_frontend phase_testing phase_qa phase_security phase_deploy claude_do"
  for fn in $required; do
    if ! grep -q "^${fn}()" "$TEAM_SH" 2>/dev/null; then
      slog "  ✗ Missing: $fn"
      score=$((score - 10))
    fi
  done

  # Pipefail safety
  local unsafe; unsafe=$(grep -c "| grep\|| awk\|| sed" "$TEAM_SH" || true)
  unsafe="${unsafe//[^0-9]/}"; unsafe="${unsafe:-0}"
  local safe; safe=$(grep -c "|| true\||| echo\||| rc=" "$TEAM_SH" || true)
  safe="${safe//[^0-9]/}"; safe="${safe:-0}"
  slog "  Pipe safety: $safe safe, $unsafe raw pipes"
  [ "$unsafe" -gt "$safe" ] && score=$((score - 10))

  # Timeout coverage
  local timeouts; timeouts=$(grep -c "timeout " "$TEAM_SH" || true)
  timeouts="${timeouts//[^0-9]/}"; timeouts="${timeouts:-0}"
  slog "  Timeouts: $timeouts"
  [ "$timeouts" -lt 2 ] && { slog "  ⚠ Low timeout coverage"; score=$((score - 10)); }

  # Lines of code
  local lines; lines=$(wc -l < "$TEAM_SH" || true)
  lines="${lines//[^0-9]/}"; lines="${lines:-0}"
  slog "  Lines: $lines"

  slog ""
  slog "  🏆 Team.sh Score: $score/100"

  python3 -c "
import json
json.dump({'score': $score, 'functions': $funcs, 'lines': $lines, 'timeouts': $timeouts, 'unsafe_pipes': $unsafe}, 
          open('$ARTIFACTS/team_verification.json', 'w'), indent=2)
" 2>/dev/null || true
}

# ── A-MASTER: Full team.sh improvement pipeline ──
run_team_improvement() {
  local steps="${1:-3}"
  slog ""
  slog "╔═══════════════════════════════════════════════╗"
  slog "║  🔧 TEAM.SH IMPROVEMENT PIPELINE ($steps steps)    ║"
  slog "╠═══════════════════════════════════════════════╣"
  slog "║  A1: 🔬 Analyze team.sh structure             ║"
  slog "║  A2: 🧠 Plan $steps specific improvements           ║"
  slog "║  A3: 🚀 Execute step-by-step with rollback    ║"
  slog "║  A4: ✅ Verify team.sh integrity               ║"
  slog "╚═══════════════════════════════════════════════╝"
  local t0; t0=$(date +%s)

  analyze_team
  plan_team_improvements "$steps"
  execute_team_improvements
  verify_team

  local elapsed=$(( $(date +%s) - t0 ))
  slog "  Team.sh pipeline done in $((elapsed/60))m $((elapsed%60))s"
}

# ═══════════════════════════════════════════════════
# TRACK B: IMPROVE PROJECT (Code)
# ═══════════════════════════════════════════════════
# (diagnose_project, plan_improvements, execute_planned_phases, verify_results — already defined above)

run_project_improvement() {
  local phases="${1:-3}"
  slog ""
  slog "╔═══════════════════════════════════════════════╗"
  slog "║  📦 PROJECT IMPROVEMENT PIPELINE ($phases phases)   ║"
  slog "╠═══════════════════════════════════════════════╣"
  slog "║  B1: 🔍 Diagnose project health               ║"
  slog "║  B2: 🧠 Plan $phases improvement phases             ║"
  slog "║  B3: 🚀 Execute each phase (full waterfall)   ║"
  slog "║  B4: ✅ Verify build/tests/types               ║"
  slog "╚═══════════════════════════════════════════════╝"
  local t0; t0=$(date +%s)

  diagnose_project
  plan_improvements "$phases"
  execute_planned_phases
  verify_results

  local elapsed=$(( $(date +%s) - t0 ))
  slog "  Project pipeline done in $((elapsed/3600))h $((elapsed%3600/60))m"
}

# Legacy / compatibility
improve_process() { run_team_improvement "${1:-3}"; }

# ═══════════════════════════════════
# STEP 3: PLAN PROJECT IMPROVEMENTS
# ═══════════════════════════════════

plan_improvements() {
  slog "🧠 STEP 3: PLANNING $AUTO_PHASES improvement phases..."

  init_phase_history
  local diagnosis; diagnosis=$(cat "$ARTIFACTS/diagnosis.json" 2>/dev/null || echo "{}")
  local project_context; project_context=$(head -c 3000 "$REPO_DIR/CLAUDE.md" 2>/dev/null || echo "No CLAUDE.md")
  local history; history=$(cat "$PHASE_HISTORY" 2>/dev/null || echo "{}")

  cd "$REPO_DIR"
  local _prompt="You are a Senior Technical Project Manager. Analyze this project and plan the next $AUTO_PHASES phases.

PROJECT (CLAUDE.md):
$project_context

DIAGNOSIS:
$diagnosis

COMPLETED ROUNDS:
$history

RULES — STRICT ORDERING:
1. CRITICAL FIRST: If build broken → Phase 1 MUST fix compilation
2. TESTS NEXT: If tests fail → Phase 2 fixes tests
3. THEN TYPESCRIPT: If TS errors → fix frontend types
4. THEN TODOS: Fix TODO/FIXME items found in code
5. THEN FEATURES: New features, missing endpoints, UI pages
6. THEN HARDENING: Security, performance, error handling
7. THEN DEVOPS: Docker, CI/CD, monitoring
8. DO NOT repeat completed rounds
9. Each description: 50-150 words, specific enough for an AI team
10. Include exact file paths, function names, endpoints where possible

RESPOND WITH ONLY JSON:
{
  \"phases\": [
    {
      \"order\": 1,
      \"name\": \"Short name (max 5 words)\",
      \"priority\": \"critical|high|medium\",
      \"category\": \"fix|feature|test|security|performance|devops\",
      \"description\": \"Detailed task description for team.sh --project. Include specific files, functions, endpoints to create/modify.\",
      \"success_criteria\": [\"go build ./... passes\", \"specific test passes\"],
      \"estimated_minutes\": 90,
      \"skip_phases\": [\"market_research\"]
    }
  ],
  \"project_health\": {
    \"score\": 75,
    \"critical_issues\": [\"issue\"],
    \"strengths\": [\"strength\"]
  },
  \"rationale\": \"Why these phases in this order\"
}"

  local claude_rc=0
  run_claude 300 "$PLAN_FILE" "$_prompt" || claude_rc=$?

  if [ "$claude_rc" -eq 124 ] || [ ! -s "$PLAN_FILE" ]; then
    swarn "  ⚠ Planning timed out or empty — skipping project improvement"
    # Create empty plan so execute doesn't crash
    echo '{"phases":[],"rationale":"Planning timed out"}' > "$PLAN_FILE"
    return 0
  fi

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
else:
    # No JSON found — write empty plan
    json.dump({"phases":[],"rationale":"No valid JSON in response"}, open(f, "w"), indent=2)
PYEOF

  # Display plan
  slog "📋 Planned phases:"
  python3 - "$PLAN_FILE" << 'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    health = d.get("project_health", {})
    print(f"  Health: {health.get('score', '?')}/100")
    for issue in health.get("critical_issues", []):
        print(f"  ⚠ {issue}")
    print()
    for p in d.get("phases", []):
        icon = {"fix":"🔧","feature":"✨","test":"🧪","security":"🔒","performance":"⚡","devops":"🐳"}.get(p.get("category",""), "📌")
        skip = p.get("skip_phases", [])
        skip_str = f" [skip: {','.join(skip)}]" if skip else ""
        print(f"  {p['order']}. {icon} [{p.get('priority','?')}] {p['name']}{skip_str}")
        print(f"     {p['description'][:100]}...")
        print(f"     ⏱ ~{p.get('estimated_minutes', '?')}min  ✓ {', '.join(p.get('success_criteria',[])[:2])}")
        print()
    print(f"  Rationale: {d.get('rationale', 'N/A')[:200]}")
except Exception as e:
    print(f"  Error reading plan: {e}")
PYEOF
}

# ═══════════════════════════════════
# STEP 4: EXECUTE PHASES
# ═══════════════════════════════════

execute_phase_round() {
  local idx="$1" total="$2"

  local phase_data; phase_data=$(python3 -c "
import json
d = json.load(open('$PLAN_FILE'))
print(d['phases'][$idx]['description'])
" 2>/dev/null || echo "")

  local phase_name; phase_name=$(python3 -c "
import json
d = json.load(open('$PLAN_FILE'))
print(d['phases'][$idx].get('name','Phase $((idx+1))'))
" 2>/dev/null || echo "Phase $((idx+1))")

  local phase_category; phase_category=$(python3 -c "
import json
d = json.load(open('$PLAN_FILE'))
print(d['phases'][$idx].get('category','feature'))
" 2>/dev/null || echo "feature")

  if [ -z "$phase_data" ]; then
    swarn "Empty phase $((idx+1)) — skipping"
    record_completed_round "EMPTY: Phase $((idx+1))" "project" "skipped"
    return 0
  fi

  slog "╔═══════════════════════════════════════╗"
  slog "║  ROUND $((idx+1))/$total: $phase_name"
  slog "╚═══════════════════════════════════════╝"
  local round_t0; round_t0=$(date +%s)

  # Reset team state for new round
  python3 - "$STATE_FILE" "$phase_data" << 'PYEOF'
import json, sys
f = sys.argv[1]
d = {"phases": {}, "project": sys.argv[2], "branch": ""}
json.dump(d, open(f, "w"), indent=2)
PYEOF

  # Run team.sh
  team_start "$phase_data"

  # Monitor until complete
  local phase_crashes=0
  local phase_done=false

  while [ "$phase_done" = false ]; do
    sleep "$HEALTH_INTERVAL"

    if ! team_is_running; then
      # Check completion
      local deploy_st; deploy_st=$(phase_status deploy)
      local sec_st; sec_st=$(phase_status security)
      local qa_st; qa_st=$(phase_status qa)

      if [ "$deploy_st" = "done" ] || [ "$sec_st" = "done" ] || [ "$qa_st" = "done" ]; then
        local elapsed=$(( $(date +%s) - round_t0 ))
        slog "✅ Round $((idx+1)) complete: $phase_name (${elapsed}s)"
        record_completed_round "$phase_name: $phase_data" "project" "done"
        phase_done=true
        continue
      fi

      phase_crashes=$((phase_crashes + 1))
      serr "💥 Crash in round $((idx+1)) (crash #$phase_crashes)"

      if [ "$phase_crashes" -ge 3 ]; then
        swarn "Too many crashes — skipping round $((idx+1))"
        record_completed_round "CRASHED: $phase_name" "project" "crashed"
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
      if ! check_phase_timeout; then
        heal_stuck
      fi
    fi
  done
}

execute_planned_phases() {
  slog "🚀 STEP 4: EXECUTING planned phases..."

  init_phase_history

  if [ ! -f "$PLAN_FILE" ]; then
    serr "No plan found. Run: ./supervisor.sh plan"
    return 1
  fi

  local total
  total=$(python3 -c "import json; print(len(json.load(open('$PLAN_FILE')).get('phases',[])))" 2>/dev/null || echo "0")

  if [ "$total" -eq 0 ]; then
    serr "No phases in plan."
    return 1
  fi

  local i=0
  while [ "$i" -lt "$total" ]; do
    execute_phase_round "$i" "$total"
    i=$((i+1))
    sleep 5
  done

  slog ""
  slog "╔═══════════════════════════════════════╗"
  slog "║  🎉 ALL $total ROUNDS COMPLETE          ║"
  slog "╚═══════════════════════════════════════╝"
}

# ═══════════════════════════════════
# STEP 5: VERIFY RESULTS
# ═══════════════════════════════════

verify_results() {
  slog "✅ STEP 5: VERIFYING results..."

  cd "$REPO_DIR"
  local score=100

  # Build
  if go build ./... 2>/dev/null; then
    slog "  ✓ Build: PASS"
  else
    slog "  ✗ Build: FAIL"
    score=$((score - 30))
  fi

  # Tests
  local test_out; test_out=$(go test ./... -count=1 -timeout 120s 2>&1 || true)
  local passed; passed=$(echo "$test_out" | grep -c "^ok " || true)
  passed="${passed//[^0-9]/}"; passed="${passed:-0}"
  local failed; failed=$(echo "$test_out" | grep -c "^FAIL" || true)
  failed="${failed//[^0-9]/}"; failed="${failed:-0}"
  if [ "$failed" -eq 0 ] 2>/dev/null; then
    slog "  ✓ Tests: ALL PASS ($passed packages)"
  else
    slog "  ⚠ Tests: $passed pass, $failed fail"
    score=$((score - 20))
  fi

  # TypeScript
  if [ -d "$REPO_DIR/frontend" ]; then
    cd "$REPO_DIR/frontend"
    # Check if tsc is available
    if [ -f node_modules/.bin/tsc ]; then
      if npx tsc --noEmit 2>/dev/null; then
        slog "  ✓ TypeScript: PASS"
      else
        local ts_err_count; ts_err_count=$(npx tsc --noEmit 2>&1 | grep -c "error TS" || true)
        ts_err_count="${ts_err_count//[^0-9]/}"; ts_err_count="${ts_err_count:-0}"
        slog "  ⚠ TypeScript: $ts_err_count errors"
        [ "$ts_err_count" -gt 0 ] 2>/dev/null && score=$((score - 10))
      fi
    else
      slog "  ⏭ TypeScript: skipped (tsc not installed)"
    fi
    cd "$REPO_DIR"
  fi

  # TODOs
  local todos; todos=$(grep -rn "TODO\|FIXME" "$REPO_DIR/internal" "$REPO_DIR/cmd" 2>/dev/null | wc -l || true)
  todos="${todos//[^0-9]/}"; todos="${todos:-0}"
  slog "  📝 TODOs remaining: $todos"
  [ "$todos" -gt 20 ] 2>/dev/null && score=$((score - 5))

  slog ""
  slog "  📊 Project Score: $score/100"

  # Save verification
  python3 -c "
import json
v = {'score': $score, 'test_passed': $passed, 'test_failed': $failed, 'todos': $todos}
json.dump(v, open('$ARTIFACTS/verification.json', 'w'), indent=2)
" 2>/dev/null || true

  return 0
}

# ═══════════════════════════════════════════════════
# MASTER: FULL IMPROVEMENT (Both Tracks)
# ═══════════════════════════════════════════════════

run_full_improvement() {
  local phases="${1:-$AUTO_PHASES}"
  local team_steps="${2:-3}"
  AUTO_PHASES="$phases"

  slog "╔═══════════════════════════════════════════════════════╗"
  slog "║  🚀 FULL IMPROVEMENT: $team_steps team + $phases project phases ║"
  slog "╠═══════════════════════════════════════════════════════╣"
  slog "║                                                       ║"
  slog "║  TRACK A: 🔧 team.sh ($team_steps steps)                      ║"
  slog "║    A1: Analyze structure, prompts, pipes              ║"
  slog "║    A2: Plan improvements                              ║"
  slog "║    A3: Execute step-by-step with rollback             ║"
  slog "║    A4: Verify integrity                               ║"
  slog "║                                                       ║"
  slog "║  TRACK B: 📦 Project ($phases phases)                       ║"
  slog "║    B1: Diagnose build/tests/types/TODOs               ║"
  slog "║    B2: Plan improvement phases                        ║"
  slog "║    B3: Execute each (full waterfall per phase)        ║"
  slog "║    B4: Verify build/tests pass                        ║"
  slog "║                                                       ║"
  slog "╚═══════════════════════════════════════════════════════╝"
  local t0; t0=$(date +%s)

  # Track A: Fix the tool first
  run_team_improvement "$team_steps"

  # Track B: Then use the improved tool to fix the project
  run_project_improvement "$phases"

  local elapsed=$(( $(date +%s) - t0 ))
  slog ""
  slog "╔═══════════════════════════════════════════════════════╗"
  slog "║  🎉 FULL IMPROVEMENT COMPLETE                         ║"
  slog "╚═══════════════════════════════════════════════════════╝"
  slog "  Time:    $((elapsed/3600))h $((elapsed%3600/60))m $((elapsed%60))s"
  slog "  Team:    $team_steps steps"
  slog "  Project: $phases phases"
  slog "  History: ./supervisor.sh history"
  slog "  Again:   ./supervisor.sh improve $phases $team_steps"
}

# Legacy aliases
plan_next_phases() { plan_improvements; }
improve_project() { run_full_improvement "${1:-$AUTO_PHASES}"; }

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

  # Check if another supervisor is running
  if [ -f "$SUP_PID" ] && kill -0 "$(cat "$SUP_PID" 2>/dev/null)" 2>/dev/null; then
    local existing; existing=$(cat "$SUP_PID" 2>/dev/null)
    if [ "$$" != "$existing" ]; then
      serr "Another supervisor running (PID: $existing). Exiting."
      exit 1
    fi
  fi

  echo $$ > "$SUP_PID"
  trap 'rm -f "$SUP_PID"; slog "Supervisor (watch) stopped"; exit 0' EXIT INT TERM

  while true; do
    sleep "$HEALTH_INTERVAL"

    # Is team.sh still running?
    if ! team_is_running; then
      # Check if it completed successfully
      local deploy_status; deploy_status=$(phase_status deploy)
      if [ "$deploy_status" = "done" ]; then
        slog "🎉 Initial build complete!"
        init_phase_history
        record_completed_round "$(get_state _meta project)" "project" "done"
        slog "Starting dual-track improvement..."
        run_full_improvement "$AUTO_PHASES" 3
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
  patch_count=$(find "$PATCHES_DIR" -maxdepth 1 -name "*.patch" 2>/dev/null | wc -l)
  patch_count="${patch_count//[^0-9]/}"
  patch_count="${patch_count:-0}"
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
for r in d.get('completed',[])[-5:]:
    cat_icon = {'team':'🔧','project':'📦','process':'⚙️'}.get(r.get('category',''),'📌')
    res_icon = {'done':'✅','failed':'❌','crashed':'💥','skipped':'⏭️'}.get(r.get('result',''),'❓')
    print(f\"    {cat_icon}{res_icon} {r.get('description','')[:65]}\")" 2>/dev/null || true
    fi
  fi

  # Team.sh plan
  if [ -f "$TEAM_PLAN_FILE" ]; then
    echo ""
    echo -e "  ${M}🔧 Team.sh improvement plan:${NC}"
    python3 -c "
import json
d = json.load(open('$TEAM_PLAN_FILE'))
for s in d.get('steps',[]):
    icon = {'crash_fix':'🔥','safety':'🛡️','prompt':'📝','retry':'🔄','new_phase':'✨','skip_logic':'⏭️','metrics':'📊','quality':'💎'}.get(s.get('category',''),'📌')
    print(f\"    {s['order']}. {icon} [{s.get('priority','?')}] {s['name']}\")" 2>/dev/null || true
  fi

  # Project plan
  if [ -f "$PLAN_FILE" ]; then
    echo ""
    echo -e "  ${B}📦 Project improvement plan:${NC}"
    python3 -c "
import json
d = json.load(open('$PLAN_FILE'))
for p in d.get('phases',[]):
    icon = {'fix':'🔧','feature':'✨','test':'🧪','security':'🔒','performance':'⚡','devops':'🐳'}.get(p.get('category',''),'📌')
    print(f\"    {p['order']}. {icon} [{p.get('priority','?')}] {p['name']}\")" 2>/dev/null || true
  fi

  # Scores
  if [ -f "$ARTIFACTS/team_verification.json" ] || [ -f "$ARTIFACTS/verification.json" ]; then
    echo ""
    python3 -c "
import json, os
t = json.load(open('$ARTIFACTS/team_verification.json')) if os.path.exists('$ARTIFACTS/team_verification.json') else {}
p = json.load(open('$ARTIFACTS/verification.json')) if os.path.exists('$ARTIFACTS/verification.json') else {}
if t: print(f\"  🏆 Team.sh Score: {t.get('score','?')}/100\")
if p: print(f\"  🏆 Project Score: {p.get('score','?')}/100\")
" 2>/dev/null || true
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
    ./supervisor.sh start "desc" [N]       # Start team + supervisor + N phases after
    ./supervisor.sh watch                  # Supervisor only (team already running)
    ./supervisor.sh restart                # Stop + resume team
    ./supervisor.sh stop                   # Stop everything
    ./supervisor.sh skip [phase]           # Skip stuck phase

  FULL IMPROVEMENT (both tracks):
    ./supervisor.sh improve [proj_N] [team_N]   # Fix team.sh + project in one run
    ./supervisor.sh next [proj_N] [team_N]      # Same as improve

  TRACK A — TEAM.SH PROCESS:
    ./supervisor.sh improve-team [N]       # Full: analyze → plan → execute → verify
    ./supervisor.sh analyze-team           # A1: Analyze structure, prompts, pipes
    ./supervisor.sh plan-team [N]          # A2: Plan N improvements to team.sh
    ./supervisor.sh execute-team           # A3: Apply improvements step-by-step
    ./supervisor.sh verify-team            # A4: Check team.sh integrity

  TRACK B — PROJECT CODE:
    ./supervisor.sh improve-project [N]    # Full: diagnose → plan → execute → verify
    ./supervisor.sh diagnose               # B1: Check build/tests/types/TODOs
    ./supervisor.sh plan [N]               # B2: Plan N project improvement phases
    ./supervisor.sh execute                # B3: Execute phases (full waterfall each)
    ./supervisor.sh verify                 # B4: Check build/tests pass

  INFO:
    ./supervisor.sh status                 # Dashboard
    ./supervisor.sh history                # Completed rounds (team + project)
    ./supervisor.sh logs                   # Supervisor log
    ./supervisor.sh patch "desc"           # Manual team.sh fix with Claude

  ┌───────────────────────────────────────────────────┐
  │  DUAL-TRACK PIPELINE                              │
  │                                                   │
  │  TRACK A: 🔧 team.sh        TRACK B: 📦 Project  │
  │  ┌──────────────────┐       ┌──────────────────┐  │
  │  │ A1: Analyze       │       │ B1: Diagnose     │  │
  │  │   prompts, pipes  │       │   build, tests   │  │
  │  ├──────────────────┤       ├──────────────────┤  │
  │  │ A2: Plan steps    │       │ B2: Plan phases  │  │
  │  │   crash→safety→   │       │   fix→test→      │  │
  │  │   prompt→quality  │       │   feature→harden │  │
  │  ├──────────────────┤       ├──────────────────┤  │
  │  │ A3: Execute 1by1  │       │ B3: Execute each │  │
  │  │   backup+rollback │       │   full waterfall │  │
  │  ├──────────────────┤       ├──────────────────┤  │
  │  │ A4: Verify        │       │ B4: Verify       │  │
  │  │   syntax+funcs    │       │   build+tests    │  │
  │  └──────────────────┘       └──────────────────┘  │
  │                                                   │
  │  Track A runs FIRST (fix the tool)                │
  │  Track B runs SECOND (use improved tool)          │
  └───────────────────────────────────────────────────┘

HELP
}

# Strip -- prefix so both "status" and "--status" work
CMD="${1:-}"
CMD="${CMD#--}"

# If running in detached mode, register PID so status/stop can find us
if [ "${_SUP_FG:-}" = "1" ]; then
  # Check if another supervisor is already running
  if [ -f "$SUP_PID" ] && kill -0 "$(cat "$SUP_PID" 2>/dev/null)" 2>/dev/null; then
    echo "  ⚠ Supervisor already running (PID: $(cat "$SUP_PID"))"
    echo "  Stop it first: ./supervisor.sh stop"
    exit 1
  fi
  echo $$ > "$SUP_PID"
  trap 'rm -f "$SUP_PID"; slog "Supervisor stopped"; exit 0' EXIT INT TERM
fi

case "$CMD" in
  start)
    [ -z "${2:-}" ] && { serr "Usage: ./supervisor.sh start \"project description\" [num_phases]"; exit 1; }
    AUTO_PHASES="${3:-3}"
    export AUTO_PHASES
    mkdir -p "$TEAM_DIR/artifacts" "$TEAM_DIR/patches" "$TEAM_DIR/logs"
    team_start "$2"
    # Fully detach supervisor: setsid + close all fds + disown
    setsid bash "$0" watch </dev/null > /dev/null 2>&1 &
    disown
    echo ""
    echo "  ✅ Supervisor + Team started (fully detached)"
    echo "  📺 tail -f $LIVE_LOG"
    echo "  📊 ./supervisor.sh status"
    echo "  🛑 ./supervisor.sh stop"
    echo "  🔄 After build: auto-plans $AUTO_PHASES improvement rounds"
    echo ""
    echo "  Safe to close SSH ✓"
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
    diagnose_project
    plan_improvements
    ;;

  execute|run)
    if [ "${_SUP_FG:-}" != "1" ]; then
      _SUP_FG=1 setsid bash "$0" "$CMD" </dev/null > /dev/null 2>&1 &
      disown
      echo "  🚀 Executing planned phases (detached)"
      echo "  📺 tail -f $SUP_LOG"
      exit 0
    fi
    execute_planned_phases
    ;;

  # ── DUAL TRACK ──
  improve|next)
    if [ "${_SUP_FG:-}" != "1" ]; then
      AUTO_PHASES="${2:-3}" _SUP_FG=1 setsid bash "$0" "$CMD" "${2:-3}" "${3:-3}" </dev/null > /dev/null 2>&1 &
      disown
      echo "  🚀 Full improvement started (detached)"
      echo "  📺 tail -f $SUP_LOG"
      echo "  📊 ./supervisor.sh status"
      echo "  Safe to close SSH ✓"
      exit 0
    fi
    AUTO_PHASES="${2:-3}"
    run_full_improvement "$AUTO_PHASES" "${3:-3}"
    ;;

  # ── TRACK A: TEAM.SH ──
  improve-team|fix-team|team)
    if [ "${_SUP_FG:-}" != "1" ]; then
      _SUP_FG=1 setsid bash "$0" "$CMD" "${2:-3}" </dev/null > /dev/null 2>&1 &
      disown
      echo "  🔧 Team.sh improvement started (detached)"
      echo "  📺 tail -f $SUP_LOG"
      exit 0
    fi
    run_team_improvement "${2:-3}"
    ;;

  analyze-team)
    analyze_team
    ;;

  plan-team)
    if [ "${_SUP_FG:-}" != "1" ]; then
      _SUP_FG=1 setsid bash "$0" "$CMD" "${2:-3}" </dev/null > /dev/null 2>&1 &
      disown
      echo "  🧠 Planning team.sh improvements (detached)"
      echo "  📺 tail -f $SUP_LOG"
      exit 0
    fi
    analyze_team
    plan_team_improvements "${2:-3}"
    ;;

  execute-team)
    if [ "${_SUP_FG:-}" != "1" ]; then
      _SUP_FG=1 setsid bash "$0" "$CMD" </dev/null > /dev/null 2>&1 &
      disown
      echo "  🚀 Executing team improvements (detached)"
      echo "  📺 tail -f $SUP_LOG"
      exit 0
    fi
    execute_team_improvements
    ;;

  verify-team)
    verify_team
    ;;

  # ── TRACK B: PROJECT ──
  improve-project|project)
    if [ "${_SUP_FG:-}" != "1" ]; then
      _SUP_FG=1 setsid bash "$0" "$CMD" "${2:-3}" </dev/null > /dev/null 2>&1 &
      disown
      echo "  📦 Project improvement started (detached)"
      echo "  📺 tail -f $SUP_LOG"
      exit 0
    fi
    run_project_improvement "${2:-3}"
    ;;

  diagnose|diag)
    diagnose_project
    ;;

  plan-project)
    AUTO_PHASES="${2:-3}"
    diagnose_project
    plan_improvements
    ;;

  verify|check)
    verify_results
    ;;

  fix-process)
    if [ "${_SUP_FG:-}" != "1" ]; then
      _SUP_FG=1 setsid bash "$0" "$CMD" "${2:-3}" </dev/null > /dev/null 2>&1 &
      disown
      echo "  🔧 Process fix started (detached)"
      echo "  📺 tail -f $SUP_LOG"
      exit 0
    fi
    run_team_improvement "${2:-3}"
    ;;

  history)
    if [ -f "$PHASE_HISTORY" ]; then
      python3 -c "
import json
d = json.load(open('$PHASE_HISTORY'))
rounds = d.get('completed', [])
team_rounds = [r for r in rounds if r.get('category') == 'team']
proj_rounds = [r for r in rounds if r.get('category') == 'project']
proc_rounds = [r for r in rounds if r.get('category') == 'process']
other = [r for r in rounds if r.get('category') not in ('team','project','process')]

print(f'Total rounds: {len(rounds)}')
print()

if team_rounds:
    print(f'🔧 TEAM.SH ({len(team_rounds)} rounds):')
    for i, r in enumerate(team_rounds, 1):
        result_icon = {'done':'✅','failed':'❌','crashed':'💥','skipped':'⏭️'}.get(r.get('result',''),'❓')
        print(f'  {i}. {result_icon} [{r.get(\"timestamp\",\"\")[:19]}] {r.get(\"description\",\"\")[:70]}')
    print()

if proj_rounds:
    print(f'📦 PROJECT ({len(proj_rounds)} rounds):')
    for i, r in enumerate(proj_rounds, 1):
        result_icon = {'done':'✅','failed':'❌','crashed':'💥','skipped':'⏭️'}.get(r.get('result',''),'❓')
        print(f'  {i}. {result_icon} [{r.get(\"timestamp\",\"\")[:19]}] {r.get(\"description\",\"\")[:70]}')
    print()

if proc_rounds or other:
    print(f'📌 OTHER ({len(proc_rounds)+len(other)} rounds):')
    for r in proc_rounds + other:
        result_icon = {'done':'✅','failed':'❌','crashed':'💥','skipped':'⏭️'}.get(r.get('result',''),'❓')
        print(f'  {result_icon} [{r.get(\"timestamp\",\"\")[:19]}] {r.get(\"description\",\"\")[:70]}')
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
