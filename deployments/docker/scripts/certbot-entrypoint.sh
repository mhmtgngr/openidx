#!/bin/bash
# ============================================================================
# OpenIDX Production - Certbot Entry Point
# Automates SSL certificate acquisition and renewal with Let's Encrypt
# ============================================================================

set -e

# Configuration from environment
DOMAIN="${CERTBOT_DOMAIN:-openidx.tdv.org}"
EMAIL="${CERTBOT_EMAIL:-admin@openidx.tdv.org}"
STAGING="${CERTBOT_STAGING:-false}"
WEBROOT="/var/www/certbot"
CONFIG_DIR="/etc/letsencrypt"
LOG_DIR="/var/log/letsencrypt"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

# Ensure webroot exists
mkdir -p "$WEBROOT"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

log "Starting Certbot for domain: $DOMAIN"

# Build certbot command arguments
CERTBOT_ARGS=(
    certonly
    --webroot
    --webroot-path="$WEBROOT"
    --email "$EMAIL"
    --agree-tos
    --non-interactive
    --domains "$DOMAIN"
    --domains "www.$DOMAIN"
    --config-dir "$CONFIG_DIR"
    --logs-dir "$LOG_DIR"
)

# Add staging flag if requested
if [ "$STAGING" = "true" ]; then
    warn "Using Let's Encrypt staging environment"
    CERTBOT_ARGS+=(--staging)
fi

# Check if certificate already exists
if [ -f "$CONFIG_DIR/live/$DOMAIN/fullchain.pem" ]; then
    log "Certificate exists for $DOMAIN, checking renewal..."

    # Check if certificate is due for renewal (less than 30 days remaining)
    openssl x509 -checkend 2592000 -noout -in "$CONFIG_DIR/live/$DOMAIN/fullchain.pem" 2>/dev/null

    if [ $? -eq 0 ]; then
        log "Certificate is still valid for more than 30 days. Skipping renewal."
        log "Certificate will be auto-renewed when needed."

        # Start renewal cron daemon for continuous operation
        log "Starting automatic renewal daemon..."
        trap exit SIGINT SIGTERM
        while true; do
            sleep $((30 * 24 * 60 * 60))  # Sleep for 30 days

            log "Running certificate renewal check..."
            certbot renew --webroot -w "$WEBROOT" \
                --config-dir "$CONFIG_DIR" \
                --logs-dir "$LOG_DIR" \
                --quiet \
                --post-hook "nginx -s reload"

            log "Renewal check completed. Next check in 30 days."
        done
    else
        log "Certificate expires in less than 30 days. Renewing now..."
    fi
else
    log "No certificate found for $DOMAIN. Requesting new certificate..."
fi

# Obtain or renew certificate
log "Executing: certbot ${CERTBOT_ARGS[*]}"
certbot "${CERTBOT_ARGS[@]}"

# Verify certificate was obtained
if [ -f "$CONFIG_DIR/live/$DOMAIN/fullchain.pem" ]; then
    log "Certificate successfully obtained!"

    # Display certificate info
    CERT_INFO=$(openssl x509 -in "$CONFIG_DIR/live/$DOMAIN/fullchain.pem" -noout -subject -dates 2>/dev/null)
    log "Certificate details:"
    echo "$CERT_INFO"

    # Calculate days until expiry
    EXPIRY_DATE=$(openssl x509 -in "$CONFIG_DIR/live/$DOMAIN/fullchain.pem" -noout -enddate | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
    CURRENT_EPOCH=$(date +%s)
    DAYS_LEFT=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

    log "Certificate valid for $DAYS_LEFT more days."

    # Test certificate reload
    if command -v nginx &> /dev/null; then
        log "Testing nginx configuration..."
        if nginx -t 2>/dev/null; then
            log "nginx configuration is valid. Reloading..."
            nginx -s reload || warn "Failed to reload nginx (may not be running yet)"
        else
            error "nginx configuration test failed!"
        fi
    fi

    # Set up automatic renewal
    log "Setting up automatic renewal..."
    trap exit SIGINT SIGTERM

    while true; do
        # Sleep until next renewal check (daily)
        sleep 86400

        # Check if renewal is needed
        log "Running daily certificate renewal check..."
        certbot renew --webroot -w "$WEBROOT" \
            --config-dir "$CONFIG_DIR" \
            --logs-dir "$LOG_DIR" \
            --quiet \
            --post-hook "nginx -s reload 2>/dev/null || true"

        log "Daily renewal check completed."
    done
else
    error "Failed to obtain certificate!"
    exit 1
fi
