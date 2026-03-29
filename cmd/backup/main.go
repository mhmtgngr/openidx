// Package main provides the database backup CLI tool for OpenIDX
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/backup"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/logger"
)

var (
	// Version information (set by build)
	Version = "dev"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New()
	defer log.Sync()

	// Load configuration
	cfg, err := config.Load("backup")
	if err != nil {
		log.Fatal("Failed to load config", zap.Error(err))
	}

	// Create backup manager from config
	manager := createBackupManager(cfg, log)

	// Execute command
	command := os.Args[1]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	switch command {
	case "create":
		handleCreate(ctx, manager, log)
	case "restore":
		handleRestore(ctx, manager, log)
	case "list", "ls":
		handleList(manager, log)
	case "verify":
		handleVerify(manager, log)
	case "schedule":
		handleSchedule(manager, log)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

// createBackupManager creates a backup manager from the application config
func createBackupManager(cfg *config.Config, log *zap.Logger) *backup.Manager {
	// Determine storage directory
	storageDir := os.Getenv("BACKUP_DIR")
	if storageDir == "" {
		storageDir = "./backups"
	}
	// Ensure storage directory exists
	os.MkdirAll(storageDir, 0700)

	// Parse database URL for database name
	dbName, _, _, _, _ := backup.ParseDatabaseURL(cfg.DatabaseURL)

	// Get encryption key from environment
	encryptionKey := os.Getenv("BACKUP_ENCRYPTION_KEY")

	// Get retention policy
	retentionCount := 7 // default
	if rc := os.Getenv("BACKUP_RETENTION_COUNT"); rc != "" {
		fmt.Sscanf(rc, "%d", &retentionCount)
	}

	// Get S3 configuration
	s3Bucket := os.Getenv("BACKUP_S3_BUCKET")
	s3Region := os.Getenv("BACKUP_S3_REGION")
	s3Endpoint := os.Getenv("BACKUP_S3_ENDPOINT")
	s3AccessKey := os.Getenv("BACKUP_S3_ACCESS_KEY")
	s3SecretKey := os.Getenv("BACKUP_S3_SECRET_KEY")

	backupCfg := &backup.BackupConfig{
		StorageDir:      storageDir,
		S3Bucket:        s3Bucket,
		S3Region:        s3Region,
		S3Endpoint:      s3Endpoint,
		S3AccessKey:     s3AccessKey,
		S3SecretKey:     s3SecretKey,
		CompressionLevel: 6,
		RetentionCount:  retentionCount,
		EncryptionKey:   encryptionKey,
		DatabaseURL:     cfg.DatabaseURL,
		DatabaseName:    dbName,
		ScheduleEnabled: false,
		ScheduleCron:    "0 2 * * *", // Default: 2 AM daily
	}

	return backup.NewManager(backupCfg, log)
}

// handleCreate handles the backup create command
func handleCreate(ctx context.Context, manager *backup.Manager, log *zap.Logger) {
	name := ""
	if len(os.Args) > 2 {
		name = os.Args[2]
	}

	result, err := manager.Create(ctx, name)
	if err != nil {
		log.Fatal("Backup failed", zap.Error(err))
	}

	fmt.Printf("\nBackup created successfully!\n")
	fmt.Printf("  Name:      %s\n", result.Name)
	fmt.Printf("  Filename:  %s\n", result.Filename)
	fmt.Printf("  Size:      %s\n", formatBytes(result.Size))
	fmt.Printf("  Encrypted: %v\n", result.Encrypted)
	fmt.Printf("  Checksum:  %s\n", result.Checksum)
	fmt.Printf("  Created:   %s\n", result.CreatedAt.Format("2006-01-02 15:04:05"))
}

// handleRestore handles the backup restore command
func handleRestore(ctx context.Context, manager *backup.Manager, log *zap.Logger) {
	if len(os.Args) < 3 {
		fmt.Println("Error: backup filename required")
		fmt.Println("Usage: backup restore <filename>")
		os.Exit(1)
	}

	filename := os.Args[2]

	// Confirm restore
	fmt.Printf("\nWARNING: This will replace the current database with backup '%s'.\n", filename)
	fmt.Print("Are you sure? (type 'yes' to confirm): ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) != "yes" {
		fmt.Println("Restore cancelled.")
		return
	}

	if err := manager.Restore(ctx, filename); err != nil {
		log.Fatal("Restore failed", zap.Error(err))
	}

	fmt.Printf("\nBackup restored successfully from '%s'!\n", filename)
}

// handleList handles the backup list command
func handleList(manager *backup.Manager, log *zap.Logger) {
	backups, err := manager.List()
	if err != nil {
		log.Fatal("Failed to list backups", zap.Error(err))
	}

	if len(backups) == 0 {
		fmt.Println("\nNo backups found.")
		return
	}

	fmt.Printf("\nFound %d backup(s):\n\n", len(backups))
	fmt.Println("Name                           Size        Encrypted   Created")
	fmt.Println("────────────────────────────────────────────────────────────────────────")

	for _, b := range backups {
		encFlag := " "
		if b.Encrypted {
			encFlag = "*"
		}
		fmt.Printf("%-30s  %-10s  %1s         %s\n",
			truncateString(b.Name, 30),
			formatBytes(b.Size),
			encFlag,
			b.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Println("────────────────────────────────────────────────────────────────────────")
	fmt.Println("* = Encrypted backup")
}

// handleVerify handles the backup verify command
func handleVerify(manager *backup.Manager, log *zap.Logger) {
	if len(os.Args) < 3 {
		fmt.Println("Error: backup filename required")
		fmt.Println("Usage: backup verify <filename>")
		os.Exit(1)
	}

	filename := os.Args[2]

	result, err := manager.Verify(filename)
	if err != nil {
		log.Fatal("Verification failed", zap.Error(err))
	}

	// Output as JSON if requested
	if len(os.Args) > 3 && os.Args[3] == "--json" {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("\nBackup Verification: %s\n\n", filename)
	fmt.Printf("  Valid:           %v\n", result.Valid)
	fmt.Printf("  Size:            %s\n", formatBytes(result.Size))
	fmt.Printf("  Created:         %s\n", result.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Encrypted:       %v\n", result.Encrypted)
	fmt.Printf("  Checksum Match:  %v\n", result.ChecksumMatch)
	fmt.Printf("  Decryptable:     %v\n", result.Decryptable)
	fmt.Printf("  Decompressible:  %v\n", result.Decompressible)

	if result.EncryptedNoKey {
		fmt.Printf("  Note:            Backup is encrypted but no decryption key provided\n")
	}

	if result.Error != "" {
		fmt.Printf("  Error:           %s\n", result.Error)
	}

	if result.Valid {
		fmt.Println("\nBackup is valid and can be restored")
	} else {
		fmt.Println("\nBackup validation failed")
	}
}

// handleSchedule handles the backup schedule command
func handleSchedule(manager *backup.Manager, log *zap.Logger) {
	schedule := manager.GetSchedule()

	fmt.Println("\nBackup Schedule Configuration")
	fmt.Println("────────────────────────────────")
	fmt.Printf("  Enabled:  %v\n", schedule.Enabled)
	fmt.Printf("  Cron:     %s\n", schedule.Cron)

	if !schedule.Enabled {
		fmt.Println("\nAutomated backups are currently disabled.")
		fmt.Println("\nTo enable scheduled backups, set the following environment variables:")
		fmt.Println("  BACKUP_SCHEDULE_ENABLED=true")
		fmt.Println("  BACKUP_SCHEDULE_CRON=\"0 2 * * *\"  # Daily at 2 AM")
		fmt.Println("\nCommon cron schedules:")
		fmt.Println("  0 2 * * *      Daily at 2:00 AM")
		fmt.Println("  0 */6 * * *    Every 6 hours")
		fmt.Println("  0 0 * * 0      Weekly on Sunday at midnight")
		fmt.Println("  0 0 1 * *      Monthly on the 1st at midnight")
	}

	// Show available backups
	fmt.Println("\nCurrent backups:")
	backups, _ := manager.List()
	if len(backups) == 0 {
		fmt.Println("  (none)")
	} else {
		for i, b := range backups {
			if i >= 5 {
				fmt.Printf("  ... and %d more\n", len(backups)-5)
				break
			}
			fmt.Printf("  - %s (%s)\n", b.Name, formatBytes(b.Size))
		}
	}
}

// printUsage displays the usage information
func printUsage() {
	fmt.Printf(`OpenIDX Database Backup Tool (v%s)

A CLI tool for creating, managing, and restoring PostgreSQL database backups.

USAGE:
    backup [command] [arguments]

COMMANDS:
    create [name]          Create a new database backup
    restore <file>         Restore database from a backup file
    list, ls               List all available backups
    verify <file>          Verify backup integrity and validity
    schedule               Show/configure automated backup schedule
    help                   Show this help message

ENVIRONMENT VARIABLES:
    DATABASE_URL           PostgreSQL connection string (required)
    BACKUP_DIR             Directory for storing backups (default: ./backups)
    BACKUP_ENCRYPTION_KEY  AES-256 encryption key for backup encryption
    BACKUP_RETENTION_COUNT Number of backups to keep (default: 7)
    BACKUP_S3_BUCKET       S3 bucket name for cloud storage (optional)
    BACKUP_S3_REGION       S3 region (optional)
    BACKUP_S3_ENDPOINT     Custom S3 endpoint (e.g., MinIO)
    BACKUP_S3_ACCESS_KEY   S3 access key (optional)
    BACKUP_S3_SECRET_KEY   S3 secret key (optional)

EXAMPLES:
    # Create a backup with auto-generated name
    backup create

    # Create a backup with custom name
    backup create production_snapshot_2026

    # Create an encrypted backup
    BACKUP_ENCRYPTION_KEY="my-secret-key" backup create

    # List all backups
    backup list

    # Verify a backup
    backup verify backup_20260327_120000.sql.gz

    # Verify a backup (JSON output)
    backup verify backup_20260327_120000.sql.gz --json

    # Restore from a backup (with confirmation)
    backup restore backup_20260327_120000.sql.gz

    # Restore an encrypted backup
    BACKUP_ENCRYPTION_KEY="my-secret-key" backup restore backup_20260327_120000.sql.gz.enc

    # Keep last 30 days of backups
    BACKUP_RETENTION_COUNT=30 backup create

    # Upload to S3 after creating backup
    BACKUP_S3_BUCKET=my-backups BACKUP_S3_REGION=us-east-1 backup create

FEATURES:
    - PostgreSQL native backups using pg_dump/psql
    - Gzip compression for reduced storage
    - AES-256-GCM encryption for security
    - SHA-256 checksums for integrity verification
    - Retention policy management
    - Local and S3-compatible cloud storage
    - Backup validation before restore

`, Version)
}

// formatBytes formats a byte size as human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
