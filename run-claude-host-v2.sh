#!/bin/bash
# run-claude-host.sh - Execute Claude Code on HOST machine from n8n container
# Uses podman to execute on host namespace

set -e

OPENIDX_REPO="${OPENIDX_REPO:-/home/cmit/openidx}"
LOG_FILE="${OPENIDX_REPO}/claude-runs.log"

log() {
    echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"
}

log "=== Claude run on HOST ==="
log "Working directory: $OPENIDX_REPO"

INSTRUCTION="$1"
BRANCH="${2:-main}"
MODEL="${3:-}"

log "Instruction: $INSTRUCTION"
log "Branch: $BRANCH"
log "Model: $MODEL"

# Write instruction to temp file for host
echo "$INSTRUCTION" > /tmp/claude-instruction.txt

# Use podman host integration to run claude on host
# This executes in the host namespace
log "Executing claude on host via podman host spawn"

# Method: Use nsenter to access host PID namespace
if [ -f "/host/proc/1/status" ]; then
    # Host filesystem is mounted at /host
    log "Using /host filesystem method"
    chroot /host /bin/bash -c "cd '$OPENIDX_REPO' && cat /tmp/claude-instruction.txt | claude -p" >> "$LOG_FILE" 2>&1
else
    # Fallback: Try to use host PID
    log "ERROR: Cannot access host filesystem"
    echo '{"status": "error", "message": "Cannot access host - mount /:/host in docker-compose.yml"}'
    exit 1
fi

if [ $? -eq 0 ]; then
    log "Command succeeded"
    echo '{"status": "success", "message": "Command completed on host"}'
    exit 0
else
    EXIT_CODE=$?
    log "Command failed with exit code $EXIT_CODE"
    echo "{\"status\": \"error\", \"message\": \"Command failed with exit code $EXIT_CODE\"}"
    exit $EXIT_CODE
fi
