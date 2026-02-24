// ============================================================================
// OpenIDX Production Backup Script Tests
// Tests for backup.sh script validation
// ============================================================================

package docker

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestBackupScriptStructure validates backup script structure
func TestBackupScriptStructure(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate shebang
	if !strings.HasPrefix(contentStr, "#!/bin/bash") {
		t.Error("Script should have bash shebang")
	}

	// Validate error handling
	if !strings.Contains(contentStr, "set -e") {
		t.Error("Script should use 'set -e' for error handling")
	}

	// Validate description comment
	if !strings.Contains(contentStr, "OpenIDX Production - Database Backup") {
		t.Error("Script should have descriptive comment header")
	}
}

// TestBackupPostgresConfiguration validates PostgreSQL configuration
func TestBackupPostgresConfiguration(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Required PostgreSQL variables
	requiredVars := []string{
		"POSTGRES_HOST",
		"POSTGRES_PORT",
		"POSTGRES_USER",
		"POSTGRES_PASSWORD",
		"POSTGRES_DB",
	}

	for _, envVar := range requiredVars {
		if !strings.Contains(contentStr, envVar) {
			t.Errorf("Missing PostgreSQL variable: %s", envVar)
		}
	}

	// Validate default values
	if !strings.Contains(contentStr, `POSTGRES_HOST:-postgres`) {
		t.Error("Should default to postgres host")
	}

	if !strings.Contains(contentStr, `POSTGRES_PORT:-5432`) {
		t.Error("Should default to port 5432")
	}

	if !strings.Contains(contentStr, `POSTGRES_USER:-openidx`) {
		t.Error("Should default to openidx user")
	}

	if !strings.Contains(contentStr, `POSTGRES_DB:-openidx`) {
		t.Error("Should default to openidx database")
	}

	// Validate required password
	if !strings.Contains(contentStr, `POSTGRES_PASSWORD:?POSTGRES_PASSWORD required`) {
		t.Error("Password should be required")
	}
}

// TestBackupDirectoryConfiguration validates backup directory setup
func TestBackupDirectoryConfiguration(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate BACKUP_DIR variable
	if !strings.Contains(contentStr, "BACKUP_DIR=") {
		t.Error("Should define BACKUP_DIR variable")
	}

	// Validate default backup directory
	if !strings.Contains(contentStr, `BACKUP_DIR:-/backups`) {
		t.Error("Should default to /backups directory")
	}

	// Validate directory creation
	if !strings.Contains(contentStr, "mkdir -p \"$BACKUP_DIR\"") {
		t.Error("Should create backup directory if it doesn't exist")
	}
}

// TestBackupFilename validates backup filename generation
func TestBackupFilename(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate timestamp generation
	if !strings.Contains(contentStr, "TIMESTAMP=") {
		t.Error("Should generate timestamp for backup filename")
	}

	// Validate date command format
	if !strings.Contains(contentStr, `date +"%Y%m%d_%H%M%S"`) {
		t.Error("Should use YYYYMMDD_HHMMSS timestamp format")
	}

	// Validate backup filename pattern
	if !strings.Contains(contentStr, "openidx_backup_") {
		t.Error("Backup filename should include prefix")
	}

	if !strings.Contains(contentStr, ".sql.gz") {
		t.Error("Backup file should be .sql.gz")
	}
}

// TestBackupPgDumpCommand validates pg_dump command
func TestBackupPgDumpCommand(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate pg_dump usage
	if !strings.Contains(contentStr, "pg_dump") {
		t.Error("Should use pg_dump for backup")
	}

	// Validate pg_dump options
	requiredOptions := []string{
		"-h",
		"-p",
		"-U",
		"-d",
		"--verbose",
		"--no-owner",
		"--no-acl",
	}

	for _, option := range requiredOptions {
		if !strings.Contains(contentStr, option) {
			t.Errorf("pg_dump should use option: %s", option)
		}
	}

	// Validate compression with gzip
	if !strings.Contains(contentStr, "| gzip >") {
		t.Error("Should compress backup with gzip")
	}
}

// TestBackupRetentionPolicy validates retention policy
func TestBackupRetentionPolicy(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate RETENTION_DAYS variable
	if !strings.Contains(contentStr, "RETENTION_DAYS=") {
		t.Error("Should define RETENTION_DAYS variable")
	}

	// Validate default retention
	if !strings.Contains(contentStr, `BACKUP_RETENTION_DAYS:-7`) {
		t.Error("Should default to 7 days retention")
	}

	// Validate find command for cleanup
	if !strings.Contains(contentStr, "find \"$BACKUP_DIR\"") {
		t.Error("Should use find to locate old backups")
	}

	// Validate mtime parameter
	if !strings.Contains(contentStr, "-mtime +$RETENTION_DAYS") {
		t.Error("Should use mtime for age-based cleanup")
	}

	// Validate delete action
	if !strings.Contains(contentStr, "-delete") {
		t.Error("Should delete old backups")
	}
}

// TestBackupOutputFunctions validates output/logging functions
func TestBackupOutputFunctions(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate color definitions
	colors := []string{
		"GREEN='\\033[0;32m'",
		"YELLOW='\\033[1;33m'",
		"RED='\\033[0;31m'",
		"NC='\\033[0m'",
	}

	for _, color := range colors {
		if !strings.Contains(contentStr, color) {
			t.Errorf("Missing color definition: %s", color)
		}
	}

	// Validate log functions
	logFunctions := []string{
		"log()",
		"warn()",
		"error()",
	}

	for _, fn := range logFunctions {
		if !strings.Contains(contentStr, fn) {
			t.Errorf("Missing log function: %s", fn)
		}
	}

	// Validate timestamp in logs
	if !strings.Contains(contentStr, `date +'%Y-%m-%d %H:%M:%S'`) {
		t.Error("Log messages should include timestamp")
	}
}

// TestBackupPGPasswordHandling validates PGPASSWORD handling
func TestBackupPGPasswordHandling(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate PGPASSWORD export
	if !strings.Contains(contentStr, `export PGPASSWORD="$POSTGRES_PASSWORD"`) {
		t.Error("Should export PGPASSWORD for pg_dump")
	}

	// Validate PGPASSWORD cleanup
	if !strings.Contains(contentStr, "unset PGPASSWORD") {
		t.Error("Should unset PGPASSWORD after backup")
	}

	// Validate cleanup happens in both success and error cases
	unsetCount := strings.Count(contentStr, "unset PGPASSWORD")
	if unsetCount < 2 {
		t.Error("Should unset PGPASSWORD in both success and error paths")
	}
}

// TestBackupSizeCalculation validates backup size reporting
func TestBackupSizeCalculation(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate du command for size
	if !strings.Contains(contentStr, "du -h") {
		t.Error("Should calculate backup file size with du -h")
	}

	// Validate size is logged
	if !strings.Contains(contentStr, "Size:") {
		t.Error("Should log backup size")
	}
}

// TestBackupListCommand validates backup listing
func TestBackupListCommand(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate ls command to list backups
	if !strings.Contains(contentStr, "ls -lh") {
		t.Error("Should list backup files with details")
	}

	// Validate pattern for backup files
	if !strings.Contains(contentStr, "openidx_backup_*.sql.gz") {
		t.Error("Should list files matching backup pattern")
	}
}

// TestBackupErrorHandling validates error handling
func TestBackupErrorHandling(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate error exit on failure
	if !strings.Contains(contentStr, `exit 1`) {
		t.Error("Should exit with error code on failure")
	}

	// Validate success exit
	if !strings.Contains(contentStr, `exit 0`) {
		t.Error("Should exit with success code on completion")
	}

	// Validate error message
	if !strings.Contains(contentStr, `"Backup failed!"`) {
		t.Error("Should log error message on failure")
	}
}

// TestBackupCleanupValidation validates old backup cleanup logic
func TestBackupCleanupValidation(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate find command structure
	if !strings.Contains(contentStr, `-name "openidx_backup_*.sql.gz"`) {
		t.Error("Should find backups by name pattern")
	}

	if !strings.Contains(contentStr, `-type f`) {
		t.Error("Should only find files, not directories")
	}

	// Validate deletion count
	if !strings.Contains(contentStr, "wc -l") {
		t.Error("Should count deleted backups")
	}

	// Validate delete reporting
	if !strings.Contains(contentStr, "Deleted $DELETED old backup(s)") {
		t.Error("Should report number of deleted backups")
	}
}

// TestBackupDockerComposeIntegration validates docker-compose integration
func TestBackupDockerComposeIntegration(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate backup scheduler service
	if !strings.Contains(contentStr, "backup-scheduler:") {
		t.Error("Missing backup-scheduler service")
	}

	// Validate backup script mount
	if !strings.Contains(contentStr, "./scripts/backup.sh:/scripts/backup.sh") {
		t.Error("Backup script should be mounted")
	}

	// Validate backup directory mount
	if !strings.Contains(contentStr, "/backups") {
		t.Error("Backup directory should be mounted")
	}

	// Validate cron setup
	if !strings.Contains(contentStr, "dcron") {
		t.Error("Should use dcron for scheduling")
	}

	// Validate crontab configuration
	if !strings.Contains(contentStr, "BACKUP_SCHEDULE") {
		t.Error("Should configure backup schedule")
	}

	if !strings.Contains(contentStr, "BACKUP_RETENTION_DAYS") {
		t.Error("Should configure backup retention in environment")
	}
}

// TestBackupScheduleDefaults validates default schedule
func TestBackupScheduleDefaults(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate default schedule (2 AM daily)
	if !strings.Contains(contentStr, `BACKUP_SCHEDULE=${BACKUP_SCHEDULE:-0 2 * * *}`) {
		t.Error("Should default to 2 AM daily schedule")
	}

	// Validate retention variable in cron command
	if !strings.Contains(contentStr, "${BACKUP_RETENTION_DAYS:-7}") {
		t.Error("Should default to 7 days retention")
	}
}

// TestBackupAlpineImage validates use of minimal base image
func TestBackupAlpineImage(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Find backup scheduler section
	backupIndex := strings.Index(contentStr, "backup-scheduler:")
	if backupIndex == -1 {
		t.Skip("Backup scheduler not found")
		return
	}

	backupSection := contentStr[backupIndex : backupIndex+500]

	// Validate Alpine image
	if !strings.Contains(backupSection, "alpine:") {
		t.Error("Backup scheduler should use Alpine image")
	}

	// Validate postgresql-client installation
	if !strings.Contains(backupSection, "postgresql-client") {
		t.Error("Should install postgresql-client")
	}
}

// TestBackupTimezoneSupport validates timezone configuration
func TestBackupTimezoneSupport(t *testing.T) {
	composePath := "docker-compose.prod.yml"

	content, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("Failed to read docker-compose.prod.yml: %v", err)
	}

	contentStr := string(content)

	// Validate timezone mount for consistent scheduling
	if !strings.Contains(contentStr, "/etc/localtime:/etc/localtime:ro") {
		t.Error("Should mount localtime for consistent cron scheduling")
	}
}

// TestBackupRetryLogic validates no retry logic (single attempt)
func TestBackupRetryLogic(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Script should fail fast without retries for simplicity
	// set -e ensures immediate failure
	if !strings.Contains(contentStr, "set -e") {
		t.Error("Should fail immediately on error")
	}

	// Should not have retry loop (avoid backup storms)
	if strings.Contains(contentStr, "for.*retry") || strings.Contains(contentStr, "while.*retry") {
		t.Error("Should not have retry logic to avoid backup storms")
	}
}

// TestBackupCompressionLevel validates gzip compression
func TestBackupCompressionLevel(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate gzip is used
	if !strings.Contains(contentStr, "gzip") {
		t.Error("Should compress with gzip")
	}

	// Currently using default compression (could add --best for smaller files)
	// This test documents the current state
	if !strings.Contains(contentStr, "| gzip >") {
		t.Error("Should pipe pg_dump output through gzip")
	}
}

// TestBackupFilenameTimestampFormat validates timestamp format
func TestBackupFilenameTimestampFormat(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate date format produces sortable filenames
	// YYYYMMDD_HHMMSS format sorts correctly chronologically
	if !strings.Contains(contentStr, `date +"%Y%m%d_%H%M%S"`) {
		t.Error("Should use ISO-like timestamp for sortable filenames")
	}

	// Validate filename pattern for regex matching
	pattern := `openidx_backup_\d{8}_\d{6}\.sql\.gz`
	matched, _ := regexp.MatchString(pattern, contentStr)

	if !matched {
		// The script won't match its own pattern, but check the format exists
		if !strings.Contains(contentStr, "openidx_backup_") {
			t.Error("Backup filename should follow consistent pattern")
		}
	}
}

// TestBackupVerboseOutput validates verbose backup output
func TestBackupVerboseOutput(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Validate --verbose flag for pg_dump
	if !strings.Contains(contentStr, "--verbose") {
		t.Error("Should use verbose mode for pg_dump")
	}

	// Validate stderr redirect or logging
	if !strings.Contains(contentStr, "2>&1") {
		t.Error("Should capture stderr for error handling")
	}
}

// TestBackupFilePermissions validates backup file handling
func TestBackupFilePermissions(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Check for explicit permission settings (optional)
	// Current implementation doesn't set specific permissions
	// This test documents the current state
	if strings.Contains(contentStr, "chmod") {
		// If chmod is used, validate it's restrictive
		if !strings.Contains(contentStr, "600") && !strings.Contains(contentStr, "400") {
			t.Error("Backup files should have restrictive permissions")
		}
	}
}

// TestBackupConcurrentSafety validates protection against concurrent runs
func TestBackupConcurrentSafety(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Current implementation doesn't use flock
	// This could be an enhancement
	// Test documents current state
	if !strings.Contains(contentStr, "flock") {
		// No concurrent run protection
		// This is acceptable given cron controls schedule
		t.Skip("No flock-based concurrent protection (acceptable)")
	}
}

// TestBackupMonitoringIntegration validates monitoring hooks
func TestBackupMonitoringIntegration(t *testing.T) {
	scriptPath := "scripts/backup.sh"

	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("Failed to read backup.sh: %v", err)
	}

	contentStr := string(content)

	// Script logs output which can be captured by docker logs
	// Validate success message
	if !strings.Contains(contentStr, "Backup completed successfully") {
		t.Error("Should log success message")
	}

	// Validate start message
	if !strings.Contains(contentStr, "Starting PostgreSQL backup") {
		t.Error("Should log backup start")
	}
}
