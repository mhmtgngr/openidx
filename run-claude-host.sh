#!/bin/bash
# run-claude-host.sh - Claude Code runner that executes on HOST machine via SSH
# This script runs inside n8n container but executes claude on the host

set -e

# Configuration
OPENIDX_REPO="${OPENIDX_REPO:-/home/cmit/openidx}"
LOG_FILE="${OPENIDX_REPO}/claude-runs.log"
HOST_IP="${HOST_IP:-172.17.0.1}"  # Default gateway = host
SSH_USER="${SSH_USER:-cmit}"
SSH_PORT="${SSH_PORT:-22}"

# Logging function
log() {
    echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"
}

log "=== Claude run on HOST via SSH ==="
log "Working directory: $OPENIDX_REPO"
log "Arguments: $*"

# Parse arguments
INSTRUCTION="$1"
BRANCH="${2:-main}"
MODEL="${3:-}"

log "Instruction: $INSTRUCTION"
log "Branch: $BRANCH"
log "Model: $MODEL"

# Build the command to run on host
CMD="cd '$OPENIDX_REPO' && claude"
if [ -n "$MODEL" ]; then
    CMD="$CMD --model $MODEL"
fi

# Execute via SSH
log "Executing on host: $CMD"

# Use sshpass or SSH keys (assuming keys are mounted)
if command -v sshpass >/dev/null 2>&1 && [ -n "$SSH_PASSWORD" ]; then
    # Using password
    echo "$INSTRUCTION" | sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "${SSH_USER}@${HOST_IP}" "$CMD" >> "$LOG_FILE" 2>&1
else
    # Using SSH keys
    echo "$INSTRUCTION" | ssh -o StrictHostKeyChecking=no -p "$SSH_PORT" "${SSH_USER}@${HOST_IP}" "$CMD" >> "$LOG_FILE" 2>&1
fi

if [ $? -eq 0 ]; then
    log "Command succeeded"
    echo '{"status": "success", "message": "Command completed successfully on host"}'
    exit 0
else
    EXIT_CODE=$?
    log "Command failed with exit code $EXIT_CODE"
    echo "{\"status\": \"error\", \"message\": \"Command failed with exit code $EXIT_CODE\", \"exit_code\": $EXIT_CODE}"
    exit $EXIT_CODE
fi
