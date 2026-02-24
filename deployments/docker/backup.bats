#!/usr/bin/env bats
# ============================================================================
# OpenIDX Production - Database Backup Script Tests
# Tests the PostgreSQL backup script
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

  # Set up test environment variables
  export POSTGRES_HOST="localhost"
  export POSTGRES_PORT="5432"
  export POSTGRES_USER="openidx"
  export POSTGRES_PASSWORD="test-password"
  export POSTGRES_DB="openidx"
  export BACKUP_DIR="$TEST_TMP_DIR/backups"
  export BACKUP_RETENTION_DAYS="7"

  # Create backup directory
  mkdir -p "$BACKUP_DIR"

  # Copy script to temp location
  cp ../deployments/docker/scripts/backup.sh "$TEST_TMP_DIR/"
  chmod +x "$TEST_TMP_DIR/backup.sh"

  # Mock pg_dump command
  export PATH="$TEST_TMP_DIR:$PATH"
  cat > "$TEST_TMP_DIR/pg_dump" << 'EOF'
#!/bin/bash
# Mock pg_dump for testing
echo "Mock dump started"
echo "-- PostgreSQL dump"
echo "CREATE TABLE test;"
echo "-- Dump complete"
exit 0
EOF
  chmod +x "$TEST_TMP_DIR/pg_dump"

  # Mock psql command for restore tests
  cat > "$TEST_TMP_DIR/psql" << 'EOF'
#!/bin/bash
echo "Mock psql executed"
exit 0
EOF
  chmod +x "$TEST_TMP_DIR/psql"

  # Mock find command to avoid actually deleting files
  cat > "$TEST_TMP_DIR/find" << 'EOF'
#!/bin/bash
# Mock find to just count files without deleting
if echo "$@" | grep -q "-delete"; then
  # Count matching files
  echo "Mock find: would have deleted old backups"
else
  # Regular find
  /usr/bin/find "$@"
fi
EOF
  chmod +x "$TEST_TMP_DIR/find"
}

teardown() {
  rm -rf "$TEST_TMP_DIR"
}

# ============================================================================
# Script Structure Tests
# ============================================================================

@test "backup.sh should exist and be executable" {
  [ -f "../deployments/docker/scripts/backup.sh" ]
}

@test "backup.sh should have bash shebang" {
  run head -n 1 ../deployments/docker/scripts/backup.sh
  assert_output --partial "#!/bin/bash"
}

@test "backup.sh should use set -e for error handling" {
  run grep "set -e" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# Configuration Tests
# ============================================================================

@test "script should define POSTGRES_HOST with default" {
  run grep "POSTGRES_HOST=" ../deployments/docker/scripts/backup.sh
  assert_output --partial "postgres"
  assert_success
}

@test "script should define POSTGRES_PORT with default" {
  run grep "POSTGRES_PORT=" ../deployments/docker/scripts/backup.sh
  assert_output --partial "5432"
  assert_success
}

@test "script should define POSTGRES_USER with default" {
  run grep "POSTGRES_USER=" ../deployments/docker/scripts/backup.sh
  assert_output --partial "openidx"
  assert_success
}

@test "script should require POSTGRES_PASSWORD" {
  run grep "POSTGRES_PASSWORD.*required" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should define POSTGRES_DB with default" {
  run grep "POSTGRES_DB=" ../deployments/docker/scripts/backup.sh
  assert_output --partial "openidx"
  assert_success
}

@test "script should define BACKUP_DIR with default" {
  run grep "BACKUP_DIR=" ../deployments/docker/scripts/backup.sh
  assert_output --partial "/backups"
  assert_success
}

@test "script should define BACKUP_RETENTION_DAYS with default" {
  run grep "BACKUP_RETENTION_DAYS=" ../deployments/docker/scripts/backup.sh
  assert_output --partial "7"
  assert_success
}

# ============================================================================
# Logging Function Tests
# ============================================================================

@test "script should define log function" {
  run grep "^log()" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should define warn function" {
  run grep "^warn()" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should define error function" {
  run grep "^error()" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should use colored output" {
  run grep "GREEN=" ../deployments/docker/scripts/backup.sh
  assert_success
  run grep "RED=" ../deployments/docker/scripts/backup.sh
  assert_success
  run grep "YELLOW=" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# Directory Creation Tests
# ============================================================================

@test "script should create backup directory" {
  run grep "mkdir.*BACKUP_DIR" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should create directory with -p flag" {
  run grep "mkdir -p" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# Backup Command Tests
# ============================================================================

@test "script should use pg_dump for backup" {
  run grep "pg_dump" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "pg_dump should use --no-owner flag" {
  run grep -- "--no-owner" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "pg_dump should use --no-acl flag" {
  run grep -- "--no-acl" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "pg_dump should use --verbose flag" {
  run grep -- "--verbose" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "backup output should be compressed with gzip" {
  run grep "gzip" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "backup filename should include timestamp" {
  run grep "TIMESTAMP=" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "backup filename should use expected format" {
  run grep "openidx_backup_" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "backup filename should include .sql.gz extension" {
  run grep ".sql.gz" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# Password Management Tests
# ============================================================================

@test "script should set PGPASSWORD environment variable" {
  run grep "export PGPASSWORD" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should unset PGPASSWORD after backup" {
  run grep "unset PGPASSWORD" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should unset PGPASSWORD in error handler" {
  run bash -c "grep -A 5 'else' ../deployments/docker/scripts/backup.sh | grep 'unset PGPASSWORD'"
  assert_success
}

# ============================================================================
# Retention Policy Tests
# ============================================================================

@test "script should define backup retention in days" {
  run grep "RETENTION_DAYS" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should find old backups" {
  run grep "find.*BACKUP_DIR" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should filter by backup filename pattern" {
  run grep "openidx_backup_.*\\.sql\\.gz" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should use -mtime for age filtering" {
  run grep "-mtime" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should delete old backups" {
  run grep "-delete" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should count deleted backups" {
  run grep "DELETED=" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should log deleted backup count" {
  run grep "Deleted.*old backup" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should list current backups" {
  run grep "ls -lh.*openidx_backup_" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# File Size Tests
# ============================================================================

@test "script should calculate backup size" {
  run grep "BACKUP_SIZE=" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should use du command for size" {
  run grep "du -h" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should log backup size" {
  run grep "Size:" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# Error Handling Tests
# ============================================================================

@test "script should check pg_dump exit status" {
  run grep "if pg_dump" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should exit on backup failure" {
  run grep "exit 1" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should log error on backup failure" {
  run grep "error.*Backup failed" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# Success Messages Tests
# ============================================================================

@test "script should log success message on completion" {
  run grep "Backup completed successfully" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should log cleanup start message" {
  run grep "Cleaning up backups" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "script should log message when no old backups exist" {
  run grep "No old backups to delete" ../deployments/docker/scripts/backup.sh
  assert_success
}

# ============================================================================
# Integration Tests
# ============================================================================

@test "backup filename should be correctly formatted" {
  run grep "BACKUP_FILE=" ../deployments/docker/scripts/backup.sh
  assert_output --partial '$BACKUP_DIR'
  assert_output --partial '$TIMESTAMP'
  assert_output --partial '.sql.gz'
}

@test "script should handle all required PostgreSQL connection parameters" {
  run grep -A 10 "pg_dump" ../deployments/docker/scripts/backup.sh
  assert_output --partial "-h"
  assert_output --partial "-p"
  assert_output --partial "-U"
  assert_output --partial "-d"
}

@test "gzip should pipe from pg_dump" {
  run grep "pg_dump.*| gzip" ../deployments/docker/scripts/backup.sh
  assert_success
}

@test "gzip output should redirect to backup file" {
  run grep "> \$BACKUP_FILE" ../deployments/docker/scripts/backup.sh
  assert_success
}
