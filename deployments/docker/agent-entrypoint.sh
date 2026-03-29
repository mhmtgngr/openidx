#!/bin/sh
set -e

CONFIG_DIR="${OPENIDX_CONFIG_DIR:-/var/lib/openidx-agent}"
CONFIG_FILE="${CONFIG_DIR}/agent.json"

# Auto-enroll if no config exists
if [ ! -f "$CONFIG_FILE" ]; then
    if [ -z "$OPENIDX_SERVER_URL" ] || [ -z "$OPENIDX_AGENT_TOKEN" ]; then
        echo "ERROR: No agent config found and OPENIDX_SERVER_URL / OPENIDX_AGENT_TOKEN not set"
        echo "  Either mount a config volume or set enrollment env vars"
        exit 1
    fi
    echo "No config found, enrolling with server..."
    openidx-agent enroll \
        --server "$OPENIDX_SERVER_URL" \
        --token "$OPENIDX_AGENT_TOKEN" \
        --config-dir "$CONFIG_DIR"
fi

echo "Starting OpenIDX agent..."
exec openidx-agent run --config-dir "$CONFIG_DIR"
