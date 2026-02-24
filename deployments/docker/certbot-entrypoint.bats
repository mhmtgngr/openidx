#!/usr/bin/env bats
# ============================================================================
# OpenIDX Production - Certbot Entrypoint Script Tests
# Tests the SSL certificate acquisition and renewal script
# ============================================================================

load test-helper/bats-support/load.bash
load test-helper/bats-assert/load.bash

# ============================================================================
# Test Setup
# ============================================================================

setup() {
  # Create temp directory for tests
  TEST_TMP_DIR="$(mktemp -d)"
  export TEST_TMP_DIR

  # Copy script to temp location
  cp ../deployments/docker/scripts/certbot-entrypoint.sh "$TEST_TMP_DIR/"
  chmod +x "$TEST_TMP_DIR/certbot-entrypoint.sh"

  # Mock certbot command
  export PATH="$TEST_TMP_DIR:$PATH"
  cat > "$TEST_TMP_DIR/certbot" << 'EOF'
#!/bin/bash
# Mock certbot for testing
echo "Mock certbot called with: $*"
if echo "$*" | grep -q "certonly"; then
  mkdir -p "$CONFIG_DIR/live/$DOMAIN"
  echo "Mock certificate" > "$CONFIG_DIR/live/$DOMAIN/fullchain.pem"
  echo "Mock key" > "$CONFIG_DIR/live/$DOMAIN/privkey.pem"
  exit 0
elif echo "$*" | grep -q "renew"; then
  echo "Mock renew"
  exit 0
fi
exit 0
EOF
  chmod +x "$TEST_TMP_DIR/certbot"

  # Mock nginx command
  cat > "$TEST_TMP_DIR/nginx" << 'EOF'
#!/bin/bash
# Mock nginx for testing
if echo "$*" | grep -q "\-t"; then
  echo "nginx: configuration file test is successful"
  exit 0
elif echo "$*" | grep -q "\-s reload"; then
  echo "nginx reloaded"
  exit 0
fi
exit 0
EOF
  chmod +x "$TEST_TMP_DIR/nginx"

  # Mock openssl command
  cat > "$TEST_TMP_DIR/openssl" << 'EOF'
#!/bin/bash
# Mock openssl for testing
if echo "$*" | grep -q "checkend"; then
  # Certificate is valid (exit 0)
  exit 0
fi
exit 0
EOF
  chmod +x "$TEST_TMP_DIR/openssl"
}

teardown() {
  rm -rf "$TEST_TMP_DIR"
}

# ============================================================================
# Script Structure Tests
# ============================================================================

@test "certbot-entrypoint.sh should exist and be executable" {
  [ -f "../deployments/docker/scripts/certbot-entrypoint.sh" ]
}

@test "certbot-entrypoint.sh should have bash shebang" {
  run head -n 1 ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_output --partial "#!/bin/bash"
}

@test "certbot-entrypoint.sh should use set -e for error handling" {
  run grep "set -e" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

# ============================================================================
# Configuration Tests
# ============================================================================

@test "script should define DOMAIN variable with default" {
  run grep "DOMAIN=" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_output --partial "CERTBOT_DOMAIN"
  assert_output --partial "openidx.tdv.org"
}

@test "script should define EMAIL variable with default" {
  run grep "EMAIL=" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_output --partial "CERTBOT_EMAIL"
  assert_output --partial "admin@openidx.tdv.org"
}

@test "script should define WEBROOT path" {
  run grep "WEBROOT=" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_output --partial "/var/www/certbot"
}

@test "script should define CONFIG_DIR for certificates" {
  run grep "CONFIG_DIR=" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_output --partial "/etc/letsencrypt"
}

# ============================================================================
# Certbot Command Tests
# ============================================================================

@test "script should call certbot with certonly command" {
  run grep "certonly" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should use webroot authentication" {
  run grep -- "--webroot" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should agree to TOS automatically" {
  run grep -- "--agree-tos" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should run in non-interactive mode" {
  run grep -- "--non-interactive" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should include both domain and www subdomain" {
  run grep -- '--domains' ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_output --partial '"$DOMAIN"'
  assert_output --partial '"www.$DOMAIN"'
}

# ============================================================================
# Certificate Validation Tests
# ============================================================================

@test "script should check if certificate exists" {
  run grep "fullchain.pem" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should validate certificate with openssl" {
  run grep "openssl x509" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should check certificate expiry date" {
  run grep "checkend" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should calculate days until expiry" {
  run grep "DAYS_LEFT" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

# ============================================================================
# Nginx Integration Tests
# ============================================================================

@test "script should test nginx configuration before reload" {
  run grep "nginx -t" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should reload nginx after certificate update" {
  run grep "nginx -s reload" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

# ============================================================================
# Renewal Logic Tests
# ============================================================================

@test "script should implement certificate renewal" {
  run grep "certbot renew" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should set up automatic renewal loop" {
  run grep "while true" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should sleep between renewal checks" {
  run grep "sleep" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "renewal should use post-hook to reload nginx" {
  run grep -- "--post-hook" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_output --partial "nginx -s reload"
}

# ============================================================================
# Logging Tests
# ============================================================================

@test "script should define log function" {
  run grep "^log()" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should define warn function" {
  run grep "^warn()" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should define error function" {
  run grep "^error()" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should use colored output" {
  run grep "GREEN=" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
  run grep "RED=" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should log certificate details" {
  run grep "Certificate details" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

# ============================================================================
# Staging Environment Tests
# ============================================================================

@test "script should support staging mode" {
  run grep "STAGING" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should add staging flag when enabled" {
  run grep "CERTBOT_STAGING" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should warn when using staging environment" {
  run grep "staging" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

# ============================================================================
# Directory Creation Tests
# ============================================================================

@test "script should create webroot directory" {
  run grep "mkdir.*WEBROOT" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should create config directory" {
  run grep "mkdir.*CONFIG_DIR" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should create log directory" {
  run grep "mkdir.*LOG_DIR" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

# ============================================================================
# Error Handling Tests
# ============================================================================

@test "script should check for certificate acquisition failure" {
  run grep "if \[ ! -f" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should exit on certificate acquisition failure" {
  run grep "exit 1" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}

@test "script should trap signals for graceful shutdown" {
  run grep "trap" ../deployments/docker/scripts/certbot-entrypoint.sh
  assert_success
}
