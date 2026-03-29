#!/bin/bash
# OpenIDX API Documentation - Local Development Server
#
# This script starts a local HTTP server to view the API documentation.
# Usage: ./serve.sh [port]
# Default port: 8080

PORT="${1:-8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "OpenIDX API Documentation Server"
echo "================================"
echo ""
echo "Starting server at http://localhost:${PORT}"
echo "Press Ctrl+C to stop"
echo ""

# Check for Python 3
if command -v python3 &> /dev/null; then
    cd "$SCRIPT_DIR"
    python3 -m http.server "$PORT"
elif command -v python &> /dev/null; then
    cd "$SCRIPT_DIR"
    python -m SimpleHTTPServer "$PORT"
else
    echo "Error: Python is not installed. Please install Python to run this server."
    exit 1
fi
