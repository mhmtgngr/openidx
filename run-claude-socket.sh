#!/bin/bash
# run-claude-socket.sh - Run Claude Code on HOST via Unix socket
# This runs in n8n container but executes on host using Podman host access

set -e

OPENIDX_REPO="${OPENIDX_REPO:-/home/cmit/openidx}"
LOG_FILE="${OPENIDX_REPO}/claude-runs.log"
HOST_SOCKET="${HOST_SOCKET:-/run/user/1000/podman/podman.sock}"

log() {
    echo "[$(date -Iseconds)] $*" >> "$LOG_FILE"
}

log "=== Claude run on HOST via socket ==="
log "Working directory: $OPENIDX_REPO"

INSTRUCTION="$1"
BRANCH="${2:-main}"
MODEL="${3:-}"

log "Instruction: $INSTRUCTION"
log "Branch: $BRANCH"

# Use nsenter to enter host namespace and run claude
# Or use podman to execute on host
if [ -S "/var/run/docker.sock" ]; then
    log "Using Podman socket to access host"

    # Create a simple wrapper script on host
    cat <<'EOF' > /tmp/claude-host-wrapper.sh
#!/bin/bash
cd "$1" || exit 1
echo "$2" | claude
EOF

    chmod +x /tmp/claude-host-wrapper.sh

    # Execute on host via podman spawning a host process
    # This requires privileged container or host PID access
    if [ -d "/host/proc" ]; then
        # Using host filesystem mount
        chroot /host /bin/bash -c "cd '$OPENIDX_REPO' && echo '$INSTRUCTION' | claude" >> "$LOG_FILE" 2>&1
    else
        log "ERROR: No host access available"
        echo '{"status": "error", "message": "Cannot access host filesystem"}'
        exit 1
    fi
else
    log "ERROR: Podman socket not available"
    echo '{"status": "error", "message": "Podman socket not mounted"}'
    exit 1
fi
