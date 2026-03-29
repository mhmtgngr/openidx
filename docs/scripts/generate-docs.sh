#!/bin/bash
# Generate reference documentation from Go source code comments
# Usage: ./docs/scripts/generate-docs.sh

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCS_DIR="$REPO_ROOT/docs/docs/reference"

# Ensure godoc2md is installed
if ! command -v godoc2md &> /dev/null; then
    echo "Installing godoc2md..."
    go install github.com/davecheney/godoc2md@latest
fi

echo "Generating Go package documentation..."

# Identity Service
echo "Generating identity.md..."
cd "$REPO_ROOT/internal/identity"
godoc2md github.com/openidx/openidx/internal/identity > "$DOCS_DIR/identity.md"

# Governance Service
echo "Generating governance.md..."
cd "$REPO_ROOT/internal/governance"
godoc2md github.com/openidx/openidx/internal/governance > "$DOCS_DIR/governance.md"

# Provisioning Service
echo "Generating provisioning.md..."
cd "$REPO_ROOT/internal/provisioning"
godoc2md github.com/openidx/openidx/internal/provisioning > "$DOCS_DIR/provisioning.md"

# Audit Service
echo "Generating audit.md..."
cd "$REPO_ROOT/internal/audit"
godoc2md github.com/openidx/openidx/internal/audit > "$DOCS_DIR/audit.md"

# OAuth Service
echo "Generating oauth.md..."
cd "$REPO_ROOT/internal/oauth"
godoc2md github.com/openidx/openidx/internal/oauth > "$DOCS_DIR/oauth.md"

# Common Middleware
echo "Generating middleware.md..."
cd "$REPO_ROOT/internal/common/middleware"
godoc2md github.com/openidx/openidx/internal/common/middleware > "$DOCS_DIR/middleware.md"

# Common Database
echo "Generating database.md..."
cd "$REPO_ROOT/internal/common/database"
godoc2md github.com/openidx/openidx/internal/common/database > "$DOCS_DIR/database.md"

echo "Documentation generated successfully!"
echo "Files written to $DOCS_DIR/"
