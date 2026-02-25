#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#
#  AI Development Team
#  ─────────────────────
#  A complete AI-powered software development team.
#  Project-agnostic: reads CLAUDE.md for context.
#
#  TEAM:
#    🧑‍💼 PM              (Z.ai / Claude)  — Requirements, user stories
#    🔍 Market Researcher (Z.ai / Claude)  — Competitor analysis, feature gaps
#    🏗️  Architect        (Z.ai / Claude)  — System design, API contracts
#    ⚙️  Backend Dev      (Claude Code)    — Implementation
#    🎨 Frontend Dev      (Claude Code)    — React/TypeScript UI
#    🧪 Tester           (Claude Code)    — Unit tests, E2E
#    📋 QA Controller     (Z.ai / Claude)  — Code review, quality gates
#    🔒 Security Auditor  (Z.ai / Claude)  — Vulnerability scan
#    🐳 DevOps           (Claude Code)    — Docker, deploy, smoke test
#
#  WATERFALL + FEEDBACK LOOPS:
#    Requirements → Market Research → Design → Backend → Frontend
#    → Testing → QA → Security → Deploy
#         ↑               |        |       |
#         └───────────────┘────────┘───────┘ (auto-fix on failure)
#
#  USAGE:
#    cd ~/your-project
#    ./team.sh --project "description"
#    ./team.sh --status
#    ./team.sh --resume
#    ./team.sh --stop
#
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Load PATH for background/nohup execution ──
for rc in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc"; do
  [ -f "$rc" ] && source "$rc" 2>/dev/null || true
done
export PATH="$HOME/go/bin:$HOME/.local/bin:$HOME/.npm-global/bin:$HOME/.nvm/versions/node/*/bin:/usr/local/go/bin:/usr/local/bin:$PATH"
[ -s "$HOME/.nvm/nvm.sh" ] && source "$HOME/.nvm/nvm.sh" 2>/dev/null || true

# ═══════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════

REPO_DIR="$PWD"
TEAM_DIR="$REPO_DIR/.team"
STATE_FILE="$TEAM_DIR/state.json"
LIVE_LOG="$TEAM_DIR/live.log"
PID_FILE="$TEAM_DIR/team.pid"
ARTIFACTS="$TEAM_DIR/artifacts"
PHASE_LOGS="$TEAM_DIR/logs"

CLAUDE_MODEL="${CLAUDE_MODEL:-opus}"
ZAI_API_KEY="${ZAI_API_KEY:-}"
ZAI_URL="${ZAI_ENDPOINT:-https://api.z.ai/api/paas/v4/chat/completions}"
ZAI_MODEL="${ZAI_MODEL:-glm-5}"
ZAI_SEARCH_URL="${ZAI_SEARCH_ENDPOINT:-https://api.z.ai/api/paas/v4/web_search}"

MAX_LOOPS=3
DOCKER_TIMEOUT=30

# Port range (auto-detected from docker-compose, or default)
SERVICE_PORTS="${SERVICE_PORTS:-}"

detect_service_ports() {
  local compose=""
  [ -f "$REPO_DIR/docker-compose.yml" ] && compose="$REPO_DIR/docker-compose.yml"
  [ -f "$REPO_DIR/deployments/docker/docker-compose.yml" ] && compose="$REPO_DIR/deployments/docker/docker-compose.yml"
  if [ -n "$compose" ] && [ -f "$compose" ]; then
    SERVICE_PORTS=$(grep -oP '"\K\d{4,5}(?=:\d)' "$compose" 2>/dev/null | sort -u | tr '\n' ' ' || true)
  fi
  if [ -z "$SERVICE_PORTS" ]; then
    SERVICE_PORTS="8500 8501 8502 8503 8504 8505 8506"
  fi
}

BRANCH=""

# Auto-detect project name from directory
PROJECT_NAME=$(basename "$REPO_DIR")

# Auto-read project context from CLAUDE.md
read_project_context() {
  if [ -f "$REPO_DIR/CLAUDE.md" ]; then
    head -c 3000 "$REPO_DIR/CLAUDE.md" 2>/dev/null
  else
    echo "Project: $PROJECT_NAME (no CLAUDE.md found)"
  fi
}

# Summarize large JSON artifacts for prompts
summarize_artifact() {
  local file="$1" max_chars="${2:-3000}"
  [ -f "$file" ] || { echo "{}"; return; }
  local size; size=$(wc -c < "$file")
  if [ "$size" -le "$max_chars" ]; then
    cat "$file"
  else
    # Extract key fields only
    python3 - "$file" "$max_chars" << 'PYEOF' 2>/dev/null || head -c "$max_chars" "$file"
import json, sys
f, max_c = sys.argv[1], int(sys.argv[2])
try:
    d = json.load(open(f))
    # For design: keep task lists, drop verbose details
    if "backend_tasks" in d:
        summary = {
            "architecture_decisions": [x.get("decision","") for x in d.get("architecture_decisions",[])[:5]],
            "backend_tasks": [{"order":x.get("order"), "file":x.get("file"), "purpose":x.get("purpose","")} for x in d.get("backend_tasks",[])],
            "frontend_tasks": [{"order":x.get("order"), "file":x.get("file"), "purpose":x.get("purpose","")} for x in d.get("frontend_tasks",[])],
            "database_migrations": [x.get("file","") for x in d.get("database_migrations",[])],
            "security_notes": d.get("security_notes",[])[:3]
        }
    # For requirements: keep essential fields
    elif "functional_requirements" in d:
        summary = {
            "project_name": d.get("project_name",""),
            "summary": d.get("summary",""),
            "functional_requirements": [{"id":x.get("id"), "title":x.get("title")} for x in d.get("functional_requirements",[])],
            "affected_services": d.get("affected_services",[]),
            "implementation_phases": d.get("implementation_phases",[])
        }
    else:
        summary = d
    result = json.dumps(summary, indent=1)
    print(result[:max_c])
except:
    print(open(f).read()[:max_c])
PYEOF
  fi
}

# ═══════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════

mkdir -p "$TEAM_DIR" "$ARTIFACTS" "$PHASE_LOGS"
touch "$LIVE_LOG"

G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'
B='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; NC='\033[0m'

log()  { echo -e "${G}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }
warn() { echo -e "${Y}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }
err()  { echo -e "${R}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }
info() { echo -e "${B}[$(date '+%H:%M:%S')]${NC} $1" | tee -a "$LIVE_LOG"; }
team() { echo -e "${M}[$(date '+%H:%M:%S')]${NC} ${W}$1${NC} $2" | tee -a "$LIVE_LOG"; }

# Error memory — record failures so we learn from them
ERROR_LOG="$TEAM_DIR/error_history.jsonl"

record_error() {
  local phase="$1" error_type="$2" detail="$3"
  python3 -c "
import json, sys
from datetime import datetime
entry = {'timestamp': datetime.now().isoformat(), 'phase': sys.argv[1], 'type': sys.argv[2], 'detail': sys.argv[3][:200]}
with open(sys.argv[4], 'a') as f:
    f.write(json.dumps(entry) + '\n')
" "$phase" "$error_type" "$detail" "$ERROR_LOG" 2>/dev/null || true
}

get_past_errors() {
  local phase="$1"
  if [ -f "$ERROR_LOG" ]; then
    python3 -c "
import json, sys
errors = []
for line in open(sys.argv[2]):
    try:
        e = json.loads(line.strip())
        if e.get('phase') == sys.argv[1]:
            errors.append(f\"- [{e['type']}] {e['detail']}\")
    except: pass
if errors:
    print('KNOWN ISSUES FROM PREVIOUS RUNS:')
    for e in errors[-5:]: print(e)
" "$phase" "$ERROR_LOG" 2>/dev/null || true
  fi
}

# ═══════════════════════════════════════════════
# STATE MANAGEMENT
# ═══════════════════════════════════════════════

state_set() {
  python3 - "$STATE_FILE" "$1" "$2" "$3" << 'PYEOF'
import json, os, sys
from datetime import datetime
f, phase, key, val = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
d = json.load(open(f)) if os.path.exists(f) else {"phases": {}, "project": "", "branch": ""}
d.setdefault("phases", {}).setdefault(phase, {})[key] = val
d["phases"][phase]["_updated"] = datetime.now().isoformat()
d["current_phase"] = phase
json.dump(d, open(f, "w"), indent=2)
PYEOF
}

state_get() {
  python3 - "$STATE_FILE" "$1" "$2" << 'PYEOF'
import json, os, sys
f, phase, key = sys.argv[1], sys.argv[2], sys.argv[3]
if not os.path.exists(f): print("pending"); exit()
d = json.load(open(f))
print(d.get("phases", {}).get(phase, {}).get(key, "pending"))
PYEOF
}

state_save_meta() {
  python3 - "$STATE_FILE" "$1" "$2" << 'PYEOF'
import json, os, sys
f, project, branch = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(f)) if os.path.exists(f) else {"phases": {}}
d["project"] = project
d["branch"] = branch
json.dump(d, open(f, "w"), indent=2)
PYEOF
}

state_get_meta() {
  python3 - "$STATE_FILE" "$1" << 'PYEOF'
import json, os, sys
f, key = sys.argv[1], sys.argv[2]
if not os.path.exists(f): print(""); exit()
print(json.load(open(f)).get(key, ""))
PYEOF
}

# ═══════════════════════════════════════════════
# Z.AI BRAIN (PM, Architect, QA, Security)
# ═══════════════════════════════════════════════

zai_think() {
  local role_name="$1" sys_file="$2" usr_file="$3" out_file="$4"
  team "$role_name" "Thinking..."

  # Truncate user prompt if too long
  local usr_content=$(cat "$usr_file")
  local prompt_len=${#usr_content}
  if [ $prompt_len -gt 8000 ]; then
    usr_content="${usr_content:0:7500}"$'\n'"[truncated $(($prompt_len - 7500)) chars]"
    echo "$usr_content" > "$usr_file"
  fi

  local req_file="$TEAM_DIR/tmp_zai_req.json"
  python3 - "$sys_file" "$usr_file" "$ZAI_MODEL" << 'PYEOF' > "$req_file"
import json, sys
req = {
    "model": sys.argv[3],
    "messages": [
        {"role": "system", "content": open(sys.argv[1]).read()},
        {"role": "user", "content": open(sys.argv[2]).read()}
    ],
    "max_tokens": 8192,
    "temperature": 0.15
}
print(json.dumps(req))
PYEOF

  local http_code
  http_code=$(curl -s -w "%{http_code}" -o "$out_file.raw" \
    -X POST "$ZAI_URL" \
    -H "Authorization: Bearer $ZAI_API_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d @"$req_file" 2>/dev/null) || http_code="000"
  rm -f "$req_file"

  if [ "$http_code" != "200" ]; then
    warn "  Z.ai HTTP $http_code"
    rm -f "$out_file.raw"
    return 1
  fi

  python3 - "$out_file.raw" "$out_file" << 'PYEOF'
import json, sys, re
try:
    r = json.load(open(sys.argv[1]))
    content = r.get("choices", [{}])[0].get("message", {}).get("content", "") or \
              r.get("choices", [{}])[0].get("message", {}).get("reasoning_content", "")
    m = re.search(r'\{[\s\S]*\}', content)
    if m:
        try:
            parsed = json.loads(m.group())
            json.dump(parsed, open(sys.argv[2], "w"), indent=2)
            exit(0)
        except json.JSONDecodeError:
            pass
    open(sys.argv[2], "w").write(content)
except Exception as e:
    json.dump({"error": str(e)}, open(sys.argv[2], "w"))
    exit(1)
PYEOF
  rm -f "$out_file.raw"
  team "$role_name" "✓ Done"
  return 0
}

ai_think() {
  local role_name="$1" sys_file="$2" usr_file="$3" out_file="$4"

  if [ -n "$ZAI_API_KEY" ]; then
    if zai_think "$role_name" "$sys_file" "$usr_file" "$out_file"; then
      local size
      size=$(wc -c < "$out_file" 2>/dev/null || echo "0")
      [ "$size" -gt 20 ] && return 0
    fi
    warn "  Z.ai failed — using Claude Code"
  fi

  team "$role_name" "Using Claude Code..."
  cd "$REPO_DIR"
  local prompt
  prompt="$(cat "$sys_file")

$(cat "$usr_file")

RESPOND WITH ONLY A JSON OBJECT. No markdown fences, no explanation."

  claude -p --model "$CLAUDE_MODEL" --dangerously-skip-permissions \
    "$prompt" > "$out_file" 2>/dev/null || true

  python3 - "$out_file" << 'PYEOF'
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
  team "$role_name" "✓ Done"
}

# ═══════════════════════════════════════════════
# Z.AI WEB SEARCH (Market Research)
# ═══════════════════════════════════════════════

zai_web_search() {
  local query="$1" out_file="$2"
  team "🔍 Research" "Searching: $query"

  # ── Try Z.ai first ──
  if [ -n "$ZAI_API_KEY" ]; then
    local req_file="$TEAM_DIR/tmp_search.json"
    python3 - "$query" << 'PYEOF' > "$req_file"
import json, sys
print(json.dumps({"query": sys.argv[1], "count": 10}))
PYEOF

    local http_code
    http_code=$(curl -s -w "%{http_code}" -o "$out_file.raw" \
      -X POST "$ZAI_SEARCH_URL" \
      -H "Authorization: Bearer $ZAI_API_KEY" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      -d @"$req_file" 2>/dev/null) || http_code="000"
    rm -f "$req_file"

    if [ "$http_code" = "200" ]; then
      python3 - "$out_file.raw" "$out_file" << 'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
    results = []
    for item in data.get("results", data.get("data", {}).get("results", [])):
        results.append({
            "title": item.get("title", ""),
            "content": item.get("content", item.get("snippet", ""))[:500],
            "url": item.get("link", item.get("url", ""))
        })
    json.dump({"results": results}, open(sys.argv[2], "w"), indent=2)
except Exception as e:
    json.dump({"results": [], "error": str(e)}, open(sys.argv[2], "w"))
PYEOF
      rm -f "$out_file.raw"
      local count
      count=$(python3 -c "import json; print(len(json.load(open('$out_file')).get('results',[])))" 2>/dev/null || echo "0")
      if [ "$count" -gt 0 ]; then
        team "🔍 Research" "✓ Z.ai found $count results"
        return 0
      fi
    fi
    rm -f "$out_file.raw"
    warn "  Z.ai search failed (HTTP $http_code) — falling back to Claude"
  fi

  # ── Fallback: Claude Code ──
  team "🔍 Research" "Using Claude Code for: $query"
  cd "$REPO_DIR"
  claude -p --model "$CLAUDE_MODEL" --dangerously-skip-permissions \
    "Search the web for: $query

Return ONLY a JSON object with search results in this exact format:
{\"results\": [{\"title\": \"page title\", \"content\": \"summary of the page content (max 500 chars)\", \"url\": \"https://...\"}]}

Return at least 5 results. No markdown, no explanation, just the JSON." \
    > "$out_file" 2>/dev/null || true

  python3 - "$out_file" << 'PYEOF'
import json, re, sys
f = sys.argv[1]
content = open(f).read()
m = re.search(r'\{[\s\S]*\}', content)
if m:
    try:
        parsed = json.loads(m.group())
        if "results" in parsed:
            json.dump(parsed, open(f, "w"), indent=2)
            exit(0)
    except: pass
json.dump({"results": [{"title": "Claude search", "content": content[:1000], "url": ""}]}, open(f, "w"), indent=2)
PYEOF

  local count
  count=$(python3 -c "import json; print(len(json.load(open('$out_file')).get('results',[])))" 2>/dev/null || echo "0")
  team "🔍 Research" "✓ Claude found $count results"
  return 0
}

market_research() {
  local out_file="$1" reqs_file="$2"
  team "🔍 Research" "Starting market analysis..."

  local ctx
  ctx=$(read_project_context | head -c 500)
  local project_type
  project_type=$(echo "$ctx" | head -5 | tr '\n' ' ')

  zai_web_search "$PROJECT_NAME $project_type competitors comparison features 2025 enterprise" \
    "$ARTIFACTS/market_competitors.json"
  zai_web_search "$PROJECT_NAME similar products features comparison best practices 2025" \
    "$ARTIFACTS/market_features.json"
  zai_web_search "$project_type trends 2025 emerging technologies best practices" \
    "$ARTIFACTS/market_trends.json"
  zai_web_search "$project_type security compliance SOC2 ISO27001 GDPR requirements 2025" \
    "$ARTIFACTS/market_compliance.json"

  python3 - "$ARTIFACTS/market_competitors.json" "$ARTIFACTS/market_features.json" \
    "$ARTIFACTS/market_trends.json" "$ARTIFACTS/market_compliance.json" \
    "$ARTIFACTS/market_combined.json" << 'PYEOF'
import json, sys
combined = {"competitors": [], "features": [], "trends": [], "compliance": []}
files = sys.argv[1:5]
keys = ["competitors", "features", "trends", "compliance"]
for f, k in zip(files, keys):
    try:
        data = json.load(open(f))
        combined[k] = data.get("results", [])
    except: pass
json.dump(combined, open(sys.argv[5], "w"), indent=2)
PYEOF

  local search_data
  search_data=$(summarize_artifact "$ARTIFACTS/market_combined.json" 4000)
  local reqs
  reqs=$(head -c 3000 "$reqs_file" 2>/dev/null || echo "{}")

  cat > "$TEAM_DIR/tmp_sys.txt" << 'PROMPT'
You are a Market Research Analyst. Analyze competitor data and identify gaps in the project.

RESPOND WITH ONLY JSON:
{
  "competitor_summary": [
    {"name": "competitor", "strengths": ["strength"], "weaknesses": ["weakness"], "pricing_model": "description"}
  ],
  "feature_comparison": [
    {"feature": "name", "competitors_with_feature": ["name"], "project_status": "implemented|partial|missing", "priority": "critical|high|medium|low", "implementation_effort": "small|medium|large"}
  ],
  "market_gaps": [
    {"gap": "description", "competitors_offering": ["name"], "business_impact": "high|medium|low", "recommended_priority": 1}
  ],
  "emerging_trends": [
    {"trend": "name", "description": "detail", "adoption_stage": "early|growing|mainstream", "relevance": "high|medium|low"}
  ],
  "compliance_gaps": [
    {"standard": "SOC2|ISO27001|GDPR|FedRAMP", "requirement": "what", "project_status": "met|partial|missing"}
  ],
  "recommended_features": [
    {"feature": "name", "description": "detail", "priority": "critical|high|medium", "effort": "small|medium|large", "competitive_advantage": "description"}
  ],
  "unique_selling_points": ["what makes this project different"],
  "summary": "2-3 paragraph market analysis"
}
PROMPT

  local project_context
  project_context=$(read_project_context)

  cat > "$TEAM_DIR/tmp_usr.txt" << PROMPT
COMPETITOR SEARCH RESULTS:
$search_data

PROJECT CONTEXT (from CLAUDE.md):
$project_context

CURRENT FEATURES (from requirements):
$reqs

Analyze the market and identify what this project is missing vs competitors.
PROMPT

  ai_think "🔍 Research" "$TEAM_DIR/tmp_sys.txt" "$TEAM_DIR/tmp_usr.txt" "$out_file"
  team "🔍 Research" "✓ Market analysis complete"
}

# ═══════════════════════════════════════════════
# CLAUDE CODE ENGINE
# ═══════════════════════════════════════════════

claude_do() {
  local role_name="$1" prompt="$2" log_file="$3"
  local timeout="${4:-900}"  # default 15 min timeout
  team "$role_name" "Working..."
  cd "$REPO_DIR"

  # Truncate prompt if too large (Claude gets Terminated on huge prompts)
  local prompt_len=${#prompt}
  if [ "$prompt_len" -gt 12000 ]; then
    warn "  Prompt too large (${prompt_len} chars) — truncating to 12000"
    prompt="${prompt:0:12000}

[TRUNCATED — original was ${prompt_len} chars. Focus on the most important parts above.]"
  fi

  local attempt=0 ok=false exit_code=0
  while [ $attempt -lt 3 ]; do
    attempt=$((attempt + 1))
    [ $attempt -gt 1 ] && warn "  ↻ Attempt $attempt/3"

    # Run with timeout
    if timeout "$timeout" claude -p --model "$CLAUDE_MODEL" --dangerously-skip-permissions \
      "$prompt" 2>&1 | tee "$log_file"; then
      ok=true; break
    fi

    exit_code=$?
    # 124 = timeout killed, 137 = SIGKILL (OOM), 143 = SIGTERM
    if [ $exit_code -eq 124 ]; then
      warn "  ⏰ Timeout after ${timeout}s"
      # Truncate prompt by 50% on timeout
      local prompt_len=${#prompt}
      prompt="${prompt:0:$(($prompt_len/2))}

[TRUNCATED after timeout — reduced from $prompt_len chars.]"
    elif [ $exit_code -ge 137 ]; then
      warn "  💀 Killed (exit $exit_code) — likely OOM or rate limit"
      # Reduce prompt further on kill
      prompt="${prompt:0:6000}

[REDUCED — Claude was killed. Simplified prompt.]"
    fi
    # Exponential backoff with jitter: 5-10s, 10-15s, 15-20s
    local wait=$((5 * attempt + RANDOM % 5))
    sleep $wait
  done

  if [ "$ok" = true ]; then
    cd "$REPO_DIR"; git add -A
    if ! git diff --cached --quiet 2>/dev/null; then
      git commit -m "[$role_name] $(echo "$prompt" | head -1 | cut -c1-60)" 2>/dev/null || true
    fi
    team "$role_name" "✓ Committed"
    return 0
  fi
  team "$role_name" "✗ Failed after $attempt attempts"
  record_error "$role_name" "claude_terminated" "Failed after $attempt attempts, last exit: $exit_code"
  return 1
}

# ═══════════════════════════════════════════════
# DOCKER / TESTS / GIT HELPERS
# ═══════════════════════════════════════════════

docker_build_all() {
  cd "$REPO_DIR"
  local ok=true total=0 built=0
  for df in deployments/docker/Dockerfile.*; do [ -f "$df" ] && total=$((total+1)); done
  [ "$total" -eq 0 ] && { warn "No Dockerfiles found"; return 0; }

  local idx=0
  for df in deployments/docker/Dockerfile.*; do
    [ -f "$df" ] || continue
    idx=$((idx+1))
    local svc; svc=$(basename "$df" | sed 's/Dockerfile\.//')
    local t0; t0=$(date +%s)
    log "  🐳 Building ($idx/$total): $svc"
    local build_rc=0
    timeout 300s podman build -f "$df" -t "${PROJECT_NAME}/${svc}:dev" . 2>&1 | tee -a "$PHASE_LOGS/docker_build.log" | tail -5 || build_rc=$?
    local elapsed=$(( $(date +%s) - t0 ))
    if [ $build_rc -eq 0 ]; then
      log "  ✓ Built: $svc (${elapsed}s)"
      built=$((built+1))
    else
      warn "  ✗ Build failed: $svc (${elapsed}s) — fixing..."
      record_error "deploy" "docker_build_fail" "$svc: $(tail -5 "$PHASE_LOGS/docker_build.log")"
      claude_do "🐳 DevOps" "Read CLAUDE.md. Docker build failed for $svc. Error:

$(tail -15 "$PHASE_LOGS/docker_build.log")

Fix the Dockerfile or source code. Rebuild should pass." \
        "$PHASE_LOGS/docker_fix_${svc}.log" 600
      podman build -f "$df" -t "${PROJECT_NAME}/${svc}:dev" . 2>&1 | tail -5 || ok=false
    fi
  done
  log "  Docker: $built/$total built"
  $ok
}

docker_up() {
  log "  🚀 Starting services..."
  cd "$REPO_DIR"
  detect_service_ports
  local compose=""
  [ -f "docker-compose.yml" ] && compose="docker-compose.yml"
  [ -f "deployments/docker/docker-compose.yml" ] && compose="deployments/docker/docker-compose.yml"
  if [ -n "$compose" ]; then
    podman-compose -f "$compose" up -d 2>&1 | tee -a "$PHASE_LOGS/docker_up.log" | tail -10 || true
    sleep "$DOCKER_TIMEOUT"
    local h=0 t=0
    for port in $SERVICE_PORTS; do
      t=$((t+1))
      (timeout 5 curl -sf --max-time 5 "http://localhost:${port}/health" >/dev/null 2>&1 && h=$((h+1)) && log "  ✓ :$port") || warn "  ✗ :$port (timeout/refused)"
    done
    log "  Health: $h/$t"
  else
    warn "  No docker-compose found"
  fi
}

docker_down() {
  cd "$REPO_DIR" 2>/dev/null || return 0
  for f in docker-compose.yml deployments/docker/docker-compose.yml; do
    [ -f "$REPO_DIR/$f" ] && podman-compose -f "$REPO_DIR/$f" down 2>/dev/null || true
  done
}

run_go_tests() {
  team "🧪 Tester" "Running Go tests..."
  cd "$REPO_DIR"
  local rc=0
  go test ./... -count=1 -timeout 180s -v 2>&1 | tee "$PHASE_LOGS/go_test.log" | tail -30 || rc=$?
  return $rc
}

fix_go_tests() {
  cd "$REPO_DIR"
  local failures
  failures=$(grep -A 3 "FAIL\|Error\|panic\|undefined\|cannot\|expected\|got:" "$PHASE_LOGS/go_test.log" 2>/dev/null | head -40 || true)
  [ -z "$failures" ] && failures=$(tail -25 "$PHASE_LOGS/go_test.log")

  record_error "testing" "go_test_fail" "$failures"
  local past; past=$(get_past_errors "testing")

  claude_do "🧪 Tester" "Read CLAUDE.md. Fix ONLY the failing Go tests:

$failures

${past:+$past

}Do NOT rewrite passing tests. Run 'go test ./...' to verify." \
    "$PHASE_LOGS/go_test_fix.log" 600
}

run_playwright() {
  local dir="$REPO_DIR/frontend"
  [ -d "$dir" ] || return 0
  team "🧪 Tester" "Running Playwright..."
  cd "$dir"
  [ -d "node_modules" ] || { npm install 2>&1 | tail -3 || true; npx playwright install --with-deps 2>&1 | tail -3 || true; }
  local rc=0
  npx playwright test --reporter=list 2>&1 | tee "$PHASE_LOGS/playwright.log" | tail -20 || rc=$?
  return $rc
}

fix_playwright() {
  cd "$REPO_DIR"
  local failures
  failures=$(grep -A 3 "FAIL\|Error\|TimeoutError\|expect\|Received" "$PHASE_LOGS/playwright.log" 2>/dev/null | head -30 || true)
  [ -z "$failures" ] && failures=$(tail -20 "$PHASE_LOGS/playwright.log")

  claude_do "🧪 Tester" "Read CLAUDE.md. Fix Playwright failures:

$failures

Verify: cd frontend && npx playwright test" \
    "$PHASE_LOGS/playwright_fix.log" 600
}

ensure_branch() {
  cd "$REPO_DIR"
  git checkout main 2>/dev/null || true
  git pull origin main 2>/dev/null || true
  git rev-parse --verify "$BRANCH" >/dev/null 2>&1 && git checkout "$BRANCH" || git checkout -b "$BRANCH"
}

merge_to_main() {
  cd "$REPO_DIR"
  git add -A && git commit -m "pre-merge" 2>/dev/null || true
  git checkout main 2>/dev/null || true
  git pull origin main 2>/dev/null || true
  if git merge "$BRANCH" --no-ff -m "Merge $BRANCH" 2>/dev/null; then
    git push origin main 2>/dev/null || true
    log "  ✓ Merged → main"
  else
    git merge --abort 2>/dev/null || true
    git merge "$BRANCH" --no-commit 2>/dev/null || true
    claude_do "🐳 DevOps" "Resolve merge conflict between $BRANCH and main. Keep both changes." "$PHASE_LOGS/merge_fix.log"
    git add -A && git commit -m "Merge $BRANCH (resolved)" 2>/dev/null || true
    git push origin main 2>/dev/null || true
  fi
}

# ═══════════════════════════════════════════════
# WATERFALL PHASES
# ═══════════════════════════════════════════════

# ──────────────────────────────
# 1. REQUIREMENTS (PM)
# ──────────────────────────────
phase_requirements() {
  local project="$1"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 1: REQUIREMENTS — 🧑‍💼 PM"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set requirements status running

  cat > "$TEAM_DIR/tmp_sys.txt" << 'PROMPT'
You are a Senior Project Manager. Read the project's CLAUDE.md for context about the tech stack, architecture, and conventions.
RESPOND WITH ONLY JSON:
{"project_name":"short","summary":"desc","user_stories":[{"id":"US-001","as_a":"role","i_want":"action","so_that":"benefit","priority":"critical|high|medium|low","acceptance_criteria":["criterion"]}],"functional_requirements":[{"id":"FR-001","title":"short","description":"detailed","service":"service_name"}],"non_functional_requirements":[{"id":"NFR-001","category":"performance|security|scalability","requirement":"desc","metric":"target"}],"api_endpoints":[{"method":"POST","path":"/api/v1/...","description":"what","roles":["admin"]}],"database_changes":[{"table":"name","action":"create|alter","columns":["col type"]}],"affected_services":["service"],"risks":[{"risk":"desc","mitigation":"plan"}],"implementation_phases":[{"phase":1,"name":"short","tasks":["task"]}]}
PROMPT

  local project_context
  project_context=$(read_project_context)

  cat > "$TEAM_DIR/tmp_usr.txt" << PROMPT
PROJECT: $project

PROJECT CONTEXT (from CLAUDE.md):
$project_context

Create comprehensive requirements.
PROMPT

  ai_think "🧑‍💼 PM" "$TEAM_DIR/tmp_sys.txt" "$TEAM_DIR/tmp_usr.txt" "$ARTIFACTS/01_requirements.json"
  state_set requirements status done
  log "✅ Requirements done"
}

# ──────────────────────────────
# 1.5 MARKET RESEARCH (Researcher)
# ──────────────────────────────
phase_market_research() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 1.5: MARKET RESEARCH — 🔍 Researcher"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set market_research status running

  market_research "$ARTIFACTS/03_market_analysis.json" "$ARTIFACTS/01_requirements.json"

  local gaps
  gaps=$(python3 -c "
import json
try:
    d = json.load(open('$ARTIFACTS/03_market_analysis.json'))
    critical = [f for f in d.get('recommended_features', []) if f.get('priority') in ('critical', 'high')]
    for f in critical[:5]:
        print(f\"• {f.get('feature','')}: {f.get('description','')}\")
    if not critical:
        print('No critical gaps found')
except: print('Analysis not available')
" 2>/dev/null || echo "Analysis not available")

  log "  Market gaps found:"
  echo "$gaps" | while read -r line; do log "    $line"; done

  python3 - "$ARTIFACTS/01_requirements.json" "$ARTIFACTS/03_market_analysis.json" << 'PYEOF'
import json, sys
try:
    reqs = json.load(open(sys.argv[1]))
    market = json.load(open(sys.argv[2]))
    existing_ids = [r.get("id","") for r in reqs.get("functional_requirements", [])]
    next_id = len(existing_ids) + 1
    for feat in market.get("recommended_features", []):
        if feat.get("priority") in ("critical", "high"):
            reqs.setdefault("functional_requirements", []).append({
                "id": f"FR-M{next_id:03d}",
                "title": feat.get("feature", ""),
                "description": feat.get("description", ""),
                "service": "identity",
                "source": "market_research",
                "competitive_advantage": feat.get("competitive_advantage", "")
            })
            next_id += 1
    reqs["market_context"] = {
        "competitors_analyzed": [c.get("name","") for c in market.get("competitor_summary", [])],
        "key_gaps": [g.get("gap","") for g in market.get("market_gaps", [])[:5]],
        "trends": [t.get("trend","") for t in market.get("emerging_trends", [])[:5]],
        "unique_selling_points": market.get("unique_selling_points", [])
    }
    json.dump(reqs, open(sys.argv[1], "w"), indent=2)
except Exception as e:
    print(f"Warning: Could not enrich requirements: {e}")
PYEOF

  state_set market_research status done
  log "✅ Market research done"
}

# ──────────────────────────────
# 2. DESIGN (Architect)
# ──────────────────────────────
phase_design() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 2: DESIGN — 🏗️  Architect"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set design status running

  cd "$REPO_DIR"
  local reqs; reqs=$(summarize_artifact "$ARTIFACTS/01_requirements.json" 4000)
  local files; files=$(find internal frontend/src \( -name "*.go" -o -name "*.tsx" \) 2>/dev/null | grep -vE '(_test|node_modules)' | sort | head -50 || true)
  local market; market=$(summarize_artifact "$ARTIFACTS/03_market_analysis.json" 2000)

  cat > "$TEAM_DIR/tmp_sys.txt" << 'PROMPT'
You are a Senior Software Architect. Read the project's CLAUDE.md for tech stack and conventions.
RESPOND WITH ONLY JSON:
{"architecture_decisions":[{"decision":"what","rationale":"why"}],"backend_tasks":[{"order":1,"file":"internal/path/file.go","action":"create|modify","purpose":"desc","key_functions":["Name"]}],"frontend_tasks":[{"order":1,"file":"frontend/src/path/File.tsx","action":"create|modify","purpose":"desc"}],"database_migrations":[{"file":"migrations/NNN_name.up.sql","sql":"CREATE TABLE..."}],"api_contracts":[{"method":"POST","path":"/api/v1/...","request":{},"response":{},"status_codes":[200,400]}],"test_plan":{"unit_tests":[{"file":"path_test.go","cases":["scenario"]}],"e2e_tests":[{"name":"test","steps":["step"]}]},"security_notes":["note"],"docker_changes":["change"],"market_driven_features":["feature incorporated from market analysis"]}
PROMPT

  local project_context
  project_context=$(read_project_context)

  cat > "$TEAM_DIR/tmp_usr.txt" << PROMPT
REQUIREMENTS (enriched with market research):
$reqs

MARKET ANALYSIS:
$market

PROJECT CONTEXT (from CLAUDE.md):
$project_context

EXISTING FILES:
$files

Design the complete solution. Include market-driven features where priority is critical/high. Be specific about file paths, function names, schemas, implementation order.
PROMPT

  ai_think "🏗️  Architect" "$TEAM_DIR/tmp_sys.txt" "$TEAM_DIR/tmp_usr.txt" "$ARTIFACTS/02_design.json"
  state_set design status done
  log "✅ Design done"
}

# ──────────────────────────────
# 3. BACKEND (Backend Dev)
# ──────────────────────────────
phase_backend() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 3: BACKEND — ⚙️  Backend Dev"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set backend status running; ensure_branch

  local design; design=$(summarize_artifact "$ARTIFACTS/02_design.json" 4000)
  local reqs; reqs=$(summarize_artifact "$ARTIFACTS/01_requirements.json" 2000)

  claude_do "⚙️  Backend" \
    "Read CLAUDE.md first. You are the Backend Developer for this project.

DESIGN: $design
REQUIREMENTS: $reqs

IMPLEMENT ALL backend files from design. Follow the patterns and conventions described in CLAUDE.md. Create migration SQL files. DO NOT write tests. Production-quality code." \
    "$PHASE_LOGS/03_backend.log"

  cd "$REPO_DIR"
  local build_ok=true
  go build ./... 2>&1 | tee "$PHASE_LOGS/03_compile.log" | tail -5 || build_ok=false
  if [ "$build_ok" = false ]; then
    record_error "backend" "compile_fail" "$(tail -10 "$PHASE_LOGS/03_compile.log")"
    local past; past=$(get_past_errors "backend")
    claude_do "⚙️  Backend" "Fix Go compilation errors:

$(tail -25 "$PHASE_LOGS/03_compile.log")

${past:+$past

}Fix ALL errors. Run 'go build ./...' to verify." "$PHASE_LOGS/03_compile_fix.log" 600
  fi

  state_set backend status done; log "✅ Backend done"
}

# ──────────────────────────────
# 4. FRONTEND (Frontend Dev)
# ──────────────────────────────
phase_frontend() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 4: FRONTEND — 🎨 Frontend Dev"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set frontend status running; ensure_branch

  local design; design=$(summarize_artifact "$ARTIFACTS/02_design.json" 4000)
  local reqs; reqs=$(summarize_artifact "$ARTIFACTS/01_requirements.json" 2000)

  claude_do "🎨 Frontend" \
    "Read CLAUDE.md first. You are the Frontend Developer for this project.

DESIGN: $design
REQUIREMENTS: $reqs

IMPLEMENT ALL frontend components/pages from design. Follow the conventions in CLAUDE.md. Create Playwright E2E tests in frontend/e2e/. Install deps if needed." \
    "$PHASE_LOGS/04_frontend.log"

  if [ -d "$REPO_DIR/frontend" ]; then
    cd "$REPO_DIR/frontend"; [ -d "node_modules" ] || npm install 2>&1 | tail -3 || true
    local ts_ok=true
    npx tsc --noEmit 2>&1 | tee "$PHASE_LOGS/04_typecheck.log" | tail -5 || ts_ok=false
    if [ "$ts_ok" = false ]; then
      record_error "frontend" "typecheck_fail" "$(tail -10 "$PHASE_LOGS/04_typecheck.log")"
      cd "$REPO_DIR"
      claude_do "🎨 Frontend" "Fix TypeScript errors:

$(grep -A 1 "error TS" "$PHASE_LOGS/04_typecheck.log" | head -25 || tail -20 "$PHASE_LOGS/04_typecheck.log")

Run 'cd frontend && npx tsc --noEmit' to verify." "$PHASE_LOGS/04_ts_fix.log" 600
    fi
  fi

  state_set frontend status done; log "✅ Frontend done"
}

# ──────────────────────────────
# 5. TESTING (Tester)
# ──────────────────────────────
phase_testing() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 5: TESTING — 🧪 Tester"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set testing status running; ensure_branch

  local design; design=$(summarize_artifact "$ARTIFACTS/02_design.json" 3000)

  # Sub-step 1: Write tests (skip if already done)
  if [ "$(state_get testing write_tests)" != "done" ]; then
    claude_do "🧪 Tester" \
      "Read CLAUDE.md first. You are the Test Engineer for this project.
DESIGN: $design
Write comprehensive tests for ALL new files following CLAUDE.md conventions. Write Playwright E2E tests in frontend/e2e/ if frontend exists. Run tests and fix failures." \
      "$PHASE_LOGS/05_tests.log" 1200
    state_set testing write_tests done
  else
    log "  ↳ Write tests already done — skipping"
  fi

  # Sub-step 2: Go tests (skip if already passed)
  if [ "$(state_get testing unit_tests)" != "passed" ]; then
    if ! run_go_tests; then
      fix_go_tests
      if ! run_go_tests; then
        warn "  Unit tests still failing — marking and continuing"
        state_set testing unit_tests failed
      else
        state_set testing unit_tests passed
      fi
    else
      state_set testing unit_tests passed
    fi
  else
    log "  ↳ Unit tests already passed — skipping"
  fi

  # Sub-step 3: E2E (skip if already done or no frontend)
  if [ "$(state_get testing e2e)" != "passed" ] && [ "$(state_get testing e2e)" != "skipped" ]; then
    if [ -d "$REPO_DIR/frontend" -o -d "$REPO_DIR/web" -o -d "$REPO_DIR/ui" ] && [ -d "$(find "$REPO_DIR" -maxdepth 2 -type d -name 'e2e' 2>/dev/null | head -1)" ]; then
      docker_build_all || true; docker_up
      if ! run_playwright; then
        fix_playwright
        run_playwright && state_set testing e2e passed || state_set testing e2e failed
      else
        state_set testing e2e passed
      fi
      docker_down
    else
      state_set testing e2e skipped
    fi
  else
    log "  ↳ E2E already done — skipping"
  fi

  cd "$REPO_DIR"; git add -A && git commit -m "[Tester] tests" 2>/dev/null || true
  state_set testing status done; log "✅ Testing done"
}

# ──────────────────────────────
# 6. QA REVIEW (QA Controller)
# ──────────────────────────────
phase_qa() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 6: QA — 📋 QA Controller"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set qa status running

  cd "$REPO_DIR"
  local diff; diff=$(git diff main --stat 2>/dev/null | tail -15 || true)
  local files; files=$(git diff main --name-only 2>/dev/null | grep "\.go$" | head -20 || true)
  local code=""; for f in $(echo "$files" | head -5); do [ -f "$f" ] && code="$code
--- $f ---
$(head -80 "$f")"; done
  local reqs; reqs=$(summarize_artifact "$ARTIFACTS/01_requirements.json" 2000)

  cat > "$TEAM_DIR/tmp_sys.txt" << 'PROMPT'
You are the QA Controller for this project. Read CLAUDE.md for context. Review strictly.
RESPOND WITH ONLY JSON:
{"overall_score":85,"verdict":"APPROVE|NEEDS_FIXES|REJECT","code_issues":[{"severity":"critical|major|minor","file":"path","issue":"desc","fix":"suggestion"}],"missing_items":["item"],"blocking_issues":["issue"],"fix_instructions":"if NEEDS_FIXES"}
PROMPT
  cat > "$TEAM_DIR/tmp_usr.txt" << PROMPT
REQUIREMENTS: $reqs
CHANGES: $diff
FILES: $files
CODE: $code
Review: error handling, validation, auth checks, HTTP codes, test coverage, API consistency.
PROMPT

  ai_think "📋 QA" "$TEAM_DIR/tmp_sys.txt" "$TEAM_DIR/tmp_usr.txt" "$ARTIFACTS/06_qa_review.json"

  local verdict; verdict=$(python3 -c "import json; print(json.load(open('$ARTIFACTS/06_qa_review.json')).get('verdict','APPROVE'))" 2>/dev/null || echo "APPROVE")
  team "📋 QA" "Verdict: $verdict"

  if [ "$verdict" = "NEEDS_FIXES" ]; then
    local fixes; fixes=$(python3 -c "
import json; d=json.load(open('$ARTIFACTS/06_qa_review.json'))
print(d.get('fix_instructions',''))
for i in d.get('blocking_issues',[]): print(f'BLOCKING: {i}')
for c in d.get('code_issues',[]):
    if c.get('severity') in ('critical','major'): print(f\"{c['severity'].upper()}: {c.get('file','')}: {c.get('issue','')} → {c.get('fix','')}\")
" 2>/dev/null || echo "Fix issues")
    claude_do "⚙️  Backend" "Read CLAUDE.md. QA found issues:
$fixes
Fix ALL blocking/critical. Run 'go test ./...'." "$PHASE_LOGS/06_qa_fix.log"
  fi

  state_set qa verdict "$verdict"; state_set qa status done; log "✅ QA: $verdict"
}

# ──────────────────────────────
# 7. SECURITY (Security Auditor)
# ──────────────────────────────
phase_security() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 7: SECURITY — 🔒 Security Auditor"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set security status running

  cd "$REPO_DIR"
  local auth=""; for f in $(find internal -name "*.go" 2>/dev/null | xargs grep -l "auth\|token\|password\|jwt\|session" 2>/dev/null | head -10 || true); do
    auth="$auth
--- $f ---
$(head -60 "$f")"; done
  local handlers=""; for f in $(find internal -name "handler*.go" -o -name "middleware*.go" 2>/dev/null | head -8 || true); do
    handlers="$handlers
--- $f ---
$(head -50 "$f")"; done

  cat > "$TEAM_DIR/tmp_sys.txt" << 'PROMPT'
You are the Security Auditor. Read CLAUDE.md for project context. SECURITY IS CRITICAL.
RESPOND WITH ONLY JSON:
{"risk_level":"low|medium|high|critical","security_score":75,"vulnerabilities":[{"id":"V-001","severity":"critical|high|medium|low","file":"path","description":"what","fix":"how"}],"owasp_checks":[{"category":"A01","status":"pass|fail","detail":""}],"verdict":"APPROVE|NEEDS_FIXES|REJECT","critical_fixes":["fix"]}
PROMPT
  cat > "$TEAM_DIR/tmp_usr.txt" << PROMPT
AUTH CODE: $auth
HANDLERS: $handlers
Check: SQL injection, XSS, CSRF, insecure JWT, weak crypto, missing auth, IDOR, data exposure. Be thorough.
PROMPT

  ai_think "🔒 Security" "$TEAM_DIR/tmp_sys.txt" "$TEAM_DIR/tmp_usr.txt" "$ARTIFACTS/07_security.json"

  local verdict; verdict=$(python3 -c "import json; print(json.load(open('$ARTIFACTS/07_security.json')).get('verdict','APPROVE'))" 2>/dev/null || echo "APPROVE")
  team "🔒 Security" "Verdict: $verdict"

  if [ "$verdict" = "NEEDS_FIXES" ] || [ "$verdict" = "REJECT" ]; then
    local fixes; fixes=$(python3 -c "
import json; d=json.load(open('$ARTIFACTS/07_security.json'))
for v in d.get('vulnerabilities',[]):
    if v.get('severity') in ('critical','high'): print(f\"{v['severity'].upper()}: {v.get('file','')}: {v.get('description','')} → {v.get('fix','')}\")
for f in d.get('critical_fixes',[]): print(f'FIX: {f}')
" 2>/dev/null || echo "Fix security issues")
    claude_do "⚙️  Backend" "Read CLAUDE.md. SECURITY FIX:
$fixes
Fix ALL critical/high vulnerabilities. Run 'go test ./...'." "$PHASE_LOGS/07_sec_fix.log"
    run_go_tests || { fix_go_tests; run_go_tests || true; }
  fi

  state_set security verdict "$verdict"; state_set security status done; log "✅ Security: $verdict"
}

# ──────────────────────────────
# 8. DEPLOY (DevOps)
# ──────────────────────────────
phase_deploy() {
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log "PHASE 8: DEPLOY — 🐳 DevOps"
  log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  state_set deploy status running

  if ! ls "$REPO_DIR/deployments/docker/Dockerfile."* >/dev/null 2>&1; then
    claude_do "🐳 DevOps" \
      "Read CLAUDE.md. Create Docker setup in deployments/docker/:
- Dockerfile for each service (multi-stage build, non-root user, HEALTHCHECK)
- docker-compose.yml with all services + PostgreSQL 16 + Redis 7, networking, health checks, volumes.
Follow the service names and ports defined in CLAUDE.md." \
      "$PHASE_LOGS/08_docker.log"
  fi

  docker_build_all || true
  docker_up

  # Smoke tests
  detect_service_ports
  team "🐳 DevOps" "Smoke testing..."
  local ok=true
  for port in $SERVICE_PORTS; do
    (timeout 5 curl -sf --max-time 5 "http://localhost:${port}/health" >/dev/null 2>&1 && log "  ✓ :$port") || { warn "  ✗ :$port (timeout/refused)"; ok=false; }
  done

  if [ "$ok" = false ]; then
    local logs=""
    for cname in $(podman ps -a --format '{{.Names}}' 2>/dev/null | grep "$PROJECT_NAME" | head -10 || true); do
      local l; l=$(podman logs "$cname" 2>&1 | tail -15); [ -n "$l" ] && logs="$logs
=== $cname ===
$l"
    done
    claude_do "🐳 DevOps" "Fix startup failures:
$logs" "$PHASE_LOGS/08_fix.log"
    docker_build_all || true; docker_down; docker_up
  fi

  [ -d "$REPO_DIR/frontend" ] && { run_playwright || true; }

  cd "$REPO_DIR"; git add -A && git commit -m "[DevOps] deploy ready" 2>/dev/null || true
  merge_to_main

  log "  🟢 Services running. Stop: ./team.sh --stop-services"
  state_set deploy status done; log "✅ Deploy done"
}

# ═══════════════════════════════════════════════
# WATERFALL ORCHESTRATOR
# ═══════════════════════════════════════════════

run_waterfall() {
  local project="$1"
  local slug; slug=$(echo "$project" | tr '[:upper:]' '[:lower:]' | tr ' ' '-' | tr -cd 'a-z0-9-' | cut -c1-40)
  BRANCH="team/${slug}-$(date +%s)"

  state_save_meta "$project" "$BRANCH"
  ensure_branch

  local t0; t0=$(date +%s)
  local loop=0
  local has_frontend=false; [ -d "$REPO_DIR/frontend" -o -d "$REPO_DIR/web" -o -d "$REPO_DIR/ui" ] && has_frontend=true

  log "╔═══════════════════════════════════════════════╗"
  log "║   AI Development Team                         ║"
  log "╠═══════════════════════════════════════════════╣"
  log "║ 🧑‍💼 PM → 🔍 Market → 🏗️ Arch → ⚙️ Back         ║"
  log "║ → 🎨 Front → 🧪 Test → 📋 QA → 🔒 Sec → 🐳      ║"
  log "╚═══════════════════════════════════════════════╝"
  log "Project: $project"
  log "Branch:  $BRANCH"

  while [ $loop -le $MAX_LOOPS ]; do
    [ $loop -gt 0 ] && warn "═══ FEEDBACK LOOP $loop/$MAX_LOOPS ═══"

    # Requirements + Market Research + Design (first pass only)
    [ $loop -eq 0 ] && { phase_requirements "$project"; phase_market_research; phase_design; }

    # Implementation
    phase_backend; [ "$has_frontend" = true ] && phase_frontend || log "  ⊘ Frontend: no frontend directory, skipping"

    # Testing gate
    phase_testing
    if [ "$(state_get testing unit_tests)" = "failed" ]; then
      err "Tests failed — looping back to fix"
      loop=$((loop+1))
      # Only reset testing sub-steps that failed, keep passed ones
      state_set testing status pending
      state_set testing unit_tests pending
      # Don't reset write_tests if done — no need to rewrite tests
      # Don't reset backend/frontend — code is fine, tests need fixing
      continue
    fi

    # QA gate
    phase_qa
    if [ "$(state_get qa verdict)" = "REJECT" ]; then
      err "QA rejected — looping back to fix code"
      loop=$((loop+1))
      # Reset implementation + testing but keep requirements/design
      state_set backend status pending
      state_set frontend status pending
      state_set testing status pending; state_set testing unit_tests pending; state_set testing write_tests pending
      state_set qa status pending
      continue
    fi

    # Security gate
    phase_security
    if [ "$(state_get security verdict)" = "REJECT" ]; then
      err "Security rejected — looping back"; loop=$((loop+1))
      state_set testing status pending; state_set qa status pending; state_set security status pending; continue
    fi

    # Deploy
    phase_deploy; break
  done

  local elapsed=$(( $(date +%s) - t0 ))
  log ""
  log "╔═══════════════════════════════════════════════╗"
  log "║   🎉 PROJECT COMPLETE                         ║"
  log "╚═══════════════════════════════════════════════╝"
  log "  Time:      $((elapsed/3600))h $((elapsed%3600/60))m"
  log "  Loops:     $loop"
  log "  Branch:    $BRANCH → main"
  log "  Artifacts: $ARTIFACTS/"
  log "  📄 Requirements: $ARTIFACTS/01_requirements.json"
  log "  🔍 Market:       $ARTIFACTS/03_market_analysis.json"
  log "  📐 Design:       $ARTIFACTS/02_design.json"
  log "  Services:  Running ($SERVICE_PORTS)"
  log "  Next:      ./team.sh --project \"next feature\""
}

# ═══════════════════════════════════════════════
# BACKGROUND EXECUTION
# ═══════════════════════════════════════════════

is_running() { [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; }

stop_team() {
  if is_running; then
    local pid; pid=$(cat "$PID_FILE")
    log "Stopping (PID: $pid)..."
    kill -TERM "$pid" 2>/dev/null || true; sleep 2; pkill -P "$pid" 2>/dev/null || true
    pkill -f "claude.*dangerously-skip-permissions" 2>/dev/null || true; rm -f "$PID_FILE"
    docker_down 2>/dev/null || true; log "✓ Stopped"
  else echo "Not running"; fi
}

launch_bg() {
  if is_running; then err "Already running ($(cat "$PID_FILE"))"; echo "  tail -f $LIVE_LOG"; exit 1; fi
  # setsid = new session (no controlling tty), </dev/null = don't block stdin
  setsid bash "$0" --fg "$@" </dev/null > /dev/null 2>&1 &
  disown
  local bg_pid=$!
  sleep 1
  # team.sh --fg writes its own PID to PID_FILE, but save bg_pid as fallback
  [ ! -f "$PID_FILE" ] && echo "$bg_pid" > "$PID_FILE"
  echo ""
  echo "  ✅ AI team running (fully detached)"
  echo "  📺 tail -f $LIVE_LOG"
  echo "  📊 ./team.sh --status"
  echo "  🛑 ./team.sh --stop"
  echo ""
  echo "  Safe to close SSH ✓"
  echo ""
  exit 0
}

# ═══════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════

show_status() {
  echo ""; echo "  ═══ AI Development Team ═══"; echo ""
  if is_running; then echo "  🔄 RUNNING (PID: $(cat "$PID_FILE" 2>/dev/null))"
    echo "  📺 tail -f $LIVE_LOG"
  else echo "  ⏹  Not running"; fi; echo ""
  [ -f "$STATE_FILE" ] && python3 - "$STATE_FILE" << 'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  Project: {d.get('project','')[:70]}")
print(f"  Branch:  {d.get('branch','')}")
print()
for p in ["requirements","market_research","design","backend","frontend","testing","qa","security","deploy"]:
    data = d.get("phases",{}).get(p,{})
    st = data.get("status","pending")
    icons = {"done":"✅","running":"🔄","pending":"⬜","failed":"❌"}
    roles = {"requirements":"🧑‍💼 PM","market_research":"🔍 Research","design":"🏗️  Arch","backend":"⚙️  Back","frontend":"🎨 Front","testing":"🧪 Test","qa":"📋 QA","security":"🔒 Sec","deploy":"🐳 DevOps"}
    v = data.get("verdict","")
    print(f"  {icons.get(st,'⬜')} {roles.get(p,p)}{f' → {v}' if v else ''}")
    for k,val in sorted(data.items()):
        if k.startswith("_") or k in ("status","verdict"): continue
        print(f"       {k}: {val}")
PYEOF
  echo ""
}

show_help() { cat << 'H'

  ╔══════════════════════════════════════╗
  ║   AI Development Team               ║
  ╚══════════════════════════════════════╝

  Just cd into your project and run.

  USAGE:
    ./team.sh --project "description"    # Full waterfall (background)
    ./team.sh --status                   # Progress
    ./team.sh --resume                   # Continue
    ./team.sh --stop                     # Stop
    ./team.sh --phase backend            # Single phase
    ./team.sh --phase market             # Market research only
    ./team.sh --project "desc" --fg      # Foreground

  PORTS: Auto-detected from docker-compose.yml (default: 8500-8506)

  ENV: ZAI_API_KEY (enables Z.ai + web search), CLAUDE_MODEL (default:opus)

H
}

PROJECT=""; PHASE=""; RESUME=false; FOREGROUND=false
while [[ $# -gt 0 ]]; do case $1 in
  --project) PROJECT="$2"; shift 2 ;; --phase) PHASE="$2"; shift 2 ;;
  --resume) RESUME=true; shift ;; --fg) FOREGROUND=true; shift ;;
  --stop) stop_team; exit 0 ;; --stop-services) docker_down; echo "✓ Stopped"; exit 0 ;;
  --status) show_status; exit 0 ;; --reset) stop_team 2>/dev/null; rm -rf "$TEAM_DIR"; echo "✓ Reset"; exit 0 ;;
  -h|--help) show_help; exit 0 ;; *) err "Unknown: $1"; show_help; exit 1 ;;
esac; done

[ -z "$PROJECT" ] && [ -z "$PHASE" ] && [ "$RESUME" = false ] && { show_help; exit 0; }

command -v claude &>/dev/null || { err "Claude Code not found. Install: npm install -g @anthropic-ai/claude-code"; exit 1; }
command -v go &>/dev/null && log "✓ go $(go version | awk '{print $3}')" || warn "⚠ go not found — backend build/test will fail"
command -v node &>/dev/null && log "✓ node $(node -v)" || warn "⚠ node not found — frontend/playwright will fail"
command -v podman &>/dev/null || command -v docker &>/dev/null || warn "⚠ podman/docker not found — deploy phase will fail"

# Auto-init git if needed
if [ ! -d "$REPO_DIR/.git" ]; then
  log "No git repo found — initializing..."
  cd "$REPO_DIR"
  git init
  git add -A
  git commit -m "Initial commit" 2>/dev/null || true
  log "✓ Git initialized"
fi

# Background by default
if [ "$FOREGROUND" = false ]; then
  [ -n "$PROJECT" ] && launch_bg --project "$PROJECT"
  [ -n "$PHASE" ] && launch_bg --phase "$PHASE"
  [ "$RESUME" = true ] && launch_bg --resume
fi

# Foreground
echo $$ > "$PID_FILE"
trap 'rm -f "$PID_FILE"; exit' EXIT INT TERM

if [ "$RESUME" = true ] && [ -f "$STATE_FILE" ]; then
  BRANCH=$(state_get_meta branch); PROJECT=$(state_get_meta project)
  [ -z "$BRANCH" ] && { err "Nothing to resume"; exit 1; }
  cd "$REPO_DIR"; git checkout "$BRANCH" 2>/dev/null || true
  cur=$(state_get_meta current_phase); log "Resuming: $cur"
  case "$cur" in
    requirements) phase_requirements "$PROJECT" ;& market_research) phase_market_research ;& design) phase_design ;& backend) phase_backend ;&
    frontend) phase_frontend ;& testing) phase_testing ;& qa) phase_qa ;&
    security) phase_security ;& deploy) phase_deploy ;; *) run_waterfall "$PROJECT" ;;
  esac
  exit 0
fi

if [ -n "$PHASE" ]; then
  BRANCH=$(state_get_meta branch); [ -z "$BRANCH" ] && BRANCH="main"
  cd "$REPO_DIR"; git checkout "$BRANCH" 2>/dev/null || true
  case "$PHASE" in
    requirements) phase_requirements "${PROJECT:-manual}" ;; market|market_research) phase_market_research ;; design) phase_design ;;
    backend) phase_backend ;; frontend) phase_frontend ;; testing) phase_testing ;;
    qa) phase_qa ;; security) phase_security ;; deploy) phase_deploy ;;
    *) err "Unknown phase: $PHASE (use: requirements|market|design|backend|frontend|testing|qa|security|deploy)" ;;
  esac; exit 0
fi

[ -n "$PROJECT" ] && run_waterfall "$PROJECT"
