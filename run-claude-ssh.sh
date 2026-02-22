#!/bin/bash
# run-claude-ssh.sh - Execute Claude Code on HOST via SSH

set -e

OPENIDX_REPO="${OPENIDX_REPO:-/home/cmit/openidx}"
LOG_FILE="${OPENIDX_REPO}/claude-runs.log"
HOST_IP="${HOST_IP:-192.168.31.76}"
SSH_USER="${SSH_USER:-cmit}"
SSH_KEY="${SSH_KEY:-/tmp/ssh/n8n_host}"

log() {
    echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"
}

log "=== Claude run on HOST via SSH ==="

INSTRUCTION="$1"
BRANCH="${2:-main}"
MODEL="${3:-}"

log "Instruction: ${INSTRUCTION:0:100}..."
log "Branch: $BRANCH"

# Use base64 to safely pass the instruction without quote issues
INSTRUCTION_B64=$(echo "$INSTRUCTION" | base64 -w 0)

# Build SSH command - decode base64 and pipe to claude with bypassPermissions
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i $SSH_KEY"
REMOTE_CMD="cd '$OPENIDX_REPO' && echo '$INSTRUCTION_B64' | base64 -d | claude -p --permission-mode bypassPermissions"

log "Executing via SSH"

if ssh $SSH_OPTS $SSH_USER@$HOST_IP "$REMOTE_CMD" >> "$LOG_FILE" 2>&1; then
    log "Command succeeded"
    echo '{"status": "success", "message": "Command completed on host via SSH"}'
    exit 0
else
    EXIT_CODE=$?
    log "Command failed with exit code $EXIT_CODE"
    echo "{\"status\": \"error\", \"message\": \"Command failed with exit code $EXIT_CODE\", \"exit_code\": $EXIT_CODE}"
    exit $EXIT_CODE
fi
