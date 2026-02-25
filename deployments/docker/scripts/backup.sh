#!/bin/bash
# ============================================================================
# OpenIDX Production - Database Backup Script
# Automates PostgreSQL backups with retention policy
# ============================================================================

set -e

# Configuration from environment
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-openidx}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD required}"
POSTGRES_DB="${POSTGRES_DB:-openidx}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/openidx_backup_$TIMESTAMP.sql.gz"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

log "Starting PostgreSQL backup for database: $POSTGRES_DB"

# Set up PostgreSQL password for pg_dump
export PGPASSWORD="$POSTGRES_PASSWORD"

# Perform backup
log "Creating backup: $BACKUP_FILE"

if pg_dump -h "$POSTGRES_HOST" \
           -p "$POSTGRES_PORT" \
           -U "$POSTGRES_USER" \
           -d "$POSTGRES_DB" \
           --verbose \
           --no-owner \
           --no-acl \
           2>&1 | gzip > "$BACKUP_FILE"; then

    # Calculate backup size
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log "Backup completed successfully! Size: $BACKUP_SIZE"

    # Clean up old backups
    log "Cleaning up backups older than $RETENTION_DAYS days..."

    DELETED=$(find "$BACKUP_DIR" \
        -name "openidx_backup_*.sql.gz" \
        -type f \
        -mtime +$RETENTION_DAYS \
        -print -delete 2>/dev/null | wc -l)

    if [ "$DELETED" -gt 0 ]; then
        log "Deleted $DELETED old backup(s)"
    else
        log "No old backups to delete"
    fi

    # List current backups
    log "Current backups:"
    ls -lh "$BACKUP_DIR"/openidx_backup_*.sql.gz 2>/dev/null || warn "No backups found"

    unset PGPASSWORD
    exit 0

else
    error "Backup failed!"
    unset PGPASSWORD
    exit 1
fi
