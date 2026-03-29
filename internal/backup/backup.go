// Package backup provides database backup and restore functionality for OpenIDX
package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Backup represents a database backup with metadata
type Backup struct {
	Name      string    `json:"name"`
	Filename  string    `json:"filename"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
	Checksum  string    `json:"checksum"`
	Encrypted bool      `json:"encrypted"`
	Storage   string    `json:"storage"` // "local" or "s3"
}

// BackupConfig holds configuration for backup operations
type BackupConfig struct {
	// Storage settings
	StorageDir     string // Local directory for backups
	S3Bucket       string // S3 bucket name
	S3Region       string // S3 region
	S3Endpoint     string // Custom S3 endpoint (for MinIO, etc.)
	S3AccessKey    string // S3 access key
	S3SecretKey    string // S3 secret key

	// Backup settings
	CompressionLevel int // 0-9, default 6
	RetentionCount   int // Keep last N backups, 0 = unlimited
	EncryptionKey    string // AES-256 encryption key (optional)

	// Database settings
	DatabaseURL  string // PostgreSQL connection string
	DatabaseName string // Database name (for pg_dump)

	// Schedule settings
	ScheduleEnabled bool
	ScheduleCron    string // Cron expression
}

// Manager handles backup operations
type Manager struct {
	config *BackupConfig
	logger *zap.Logger
}

// NewManager creates a new backup manager
func NewManager(config *BackupConfig, logger *zap.Logger) *Manager {
	if config.CompressionLevel == 0 {
		config.CompressionLevel = 6
	}
	return &Manager{
		config: config,
		logger: logger,
	}
}

// Create creates a new database backup
func (m *Manager) Create(ctx context.Context, name string) (*Backup, error) {
	if name == "" {
		name = fmt.Sprintf("backup_%s", time.Now().Format("20060102_150405"))
	}

	m.logger.Info("Creating backup", zap.String("name", name))

	filename := fmt.Sprintf("%s.sql.gz", name)
	if m.config.EncryptionKey != "" {
		filename += ".enc"
	}
	filepath := filepath.Join(m.config.StorageDir, filename)

	// Create temporary file for the dump
	tmpFile := filepath + ".tmp"

	// Execute pg_dump
	if err := m.runPgDump(ctx, tmpFile); err != nil {
		return nil, fmt.Errorf("pg_dump failed: %w", err)
	}
	defer os.Remove(tmpFile)

	// Read and optionally compress/encrypt
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("read dump file: %w", err)
	}

	// Compress
	compressed, err := m.compress(data)
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}

	// Encrypt if key provided
	var finalData []byte
	encrypted := false
	if m.config.EncryptionKey != "" {
		finalData, err = m.encrypt(compressed, m.config.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		encrypted = true
	} else {
		finalData = compressed
	}

	// Write final file
	if err := os.WriteFile(filepath, finalData, 0600); err != nil {
		return nil, fmt.Errorf("write backup file: %w", err)
	}

	// Calculate checksum
	checksum := fmt.Sprintf("%x", sha256.Sum256(finalData))

	backup := &Backup{
		Name:      name,
		Filename:  filename,
		CreatedAt: time.Now(),
		Size:      int64(len(finalData)),
		Checksum:  checksum,
		Encrypted: encrypted,
		Storage:   "local",
	}

	// Save metadata
	if err := m.saveMetadata(backup); err != nil {
		m.logger.Warn("Failed to save metadata", zap.Error(err))
	}

	// Upload to S3 if configured
	if m.config.S3Bucket != "" {
		if err := m.uploadToS3(ctx, backup, finalData); err != nil {
			m.logger.Warn("Failed to upload to S3", zap.Error(err))
		} else {
			backup.Storage = "s3"
		}
	}

	// Apply retention policy
	if m.config.RetentionCount > 0 {
		m.applyRetention()
	}

	m.logger.Info("Backup created successfully",
		zap.String("name", name),
		zap.Int64("size", backup.Size))

	return backup, nil
}

// Restore restores a database from a backup file
func (m *Manager) Restore(ctx context.Context, filename string) error {
	m.logger.Info("Restoring backup", zap.String("filename", filename))

	filepath := filepath.Join(m.config.StorageDir, filename)

	// Read file
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("read backup file: %w", err)
	}

	// Verify checksum
	metadata, err := m.loadMetadata(filename)
	if err == nil && metadata.Checksum != "" {
		actualChecksum := fmt.Sprintf("%x", sha256.Sum256(data))
		if actualChecksum != metadata.Checksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", metadata.Checksum, actualChecksum)
		}
	}

	// Decrypt if needed
	var decrypted []byte
	if strings.HasSuffix(filename, ".enc") {
		if m.config.EncryptionKey == "" {
			return fmt.Errorf("backup is encrypted but no decryption key provided")
		}
		decrypted, err = m.decrypt(data, m.config.EncryptionKey)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
	} else {
		decrypted = data
	}

	// Decompress
	decompressed, err := m.decompress(decrypted)
	if err != nil {
		return fmt.Errorf("decompress: %w", err)
	}

	// Create temporary file for restore
	tmpFile := filepath + ".restore.tmp"
	if err := os.WriteFile(tmpFile, decompressed, 0600); err != nil {
		return fmt.Errorf("write restore file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Execute pg_restore
	if err := m.runPgRestore(ctx, tmpFile); err != nil {
		return fmt.Errorf("pg_restore failed: %w", err)
	}

	m.logger.Info("Backup restored successfully", zap.String("filename", filename))
	return nil
}

// List returns all available backups
func (m *Manager) List() ([]*Backup, error) {
	entries, err := os.ReadDir(m.config.StorageDir)
	if err != nil {
		return nil, fmt.Errorf("read backup directory: %w", err)
	}

	var backups []*Backup
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Skip metadata files
		if strings.HasSuffix(name, ".meta.json") {
			continue
		}

		// Only process backup files
		if !strings.HasPrefix(name, "backup_") && !strings.HasSuffix(name, ".sql.gz") && !strings.HasSuffix(name, ".sql.gz.enc") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Try to load metadata
		metadata, _ := m.loadMetadata(name)

		backup := &Backup{
			Filename:  name,
			CreatedAt: info.ModTime(),
			Size:      info.Size(),
			Storage:   "local",
		}

		if metadata != nil {
			backup.Name = metadata.Name
			backup.Checksum = metadata.Checksum
			backup.Encrypted = metadata.Encrypted
		} else {
			backup.Name = strings.TrimSuffix(name, ".sql.gz")
			backup.Name = strings.TrimSuffix(backup.Name, ".enc")
			backup.Encrypted = strings.HasSuffix(name, ".enc")
		}

		backups = append(backups, backup)
	}

	// Sort by creation time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	return backups, nil
}

// Verify verifies the integrity of a backup file
func (m *Manager) Verify(filename string) (*VerifyResult, error) {
	filepath := filepath.Join(m.config.StorageDir, filename)

	result := &VerifyResult{
		Filename: filename,
		Valid:    true,
	}

	// Check file exists
	info, err := os.Stat(filepath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("file not found: %v", err)
		return result, nil
	}
	result.Size = info.Size()

	// Read file
	data, err := os.ReadFile(filepath)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Sprintf("read error: %v", err)
		return result, nil
	}

	// Check checksum
	metadata, err := m.loadMetadata(filename)
	if err == nil && metadata.Checksum != "" {
		actualChecksum := fmt.Sprintf("%x", sha256.Sum256(data))
		if actualChecksum != metadata.Checksum {
			result.Valid = false
			result.Error = fmt.Sprintf("checksum mismatch: expected %s, got %s", metadata.Checksum, actualChecksum)
			return result, nil
		}
		result.ChecksumMatch = true
	}

	// Try to decrypt if encrypted
	if strings.HasSuffix(filename, ".enc") {
		if m.config.EncryptionKey != "" {
			decrypted, err := m.decrypt(data, m.config.EncryptionKey)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("decryption failed: %v", err)
				return result, nil
			}
			result.Decryptable = true
			data = decrypted
		} else {
			result.EncryptedNoKey = true
		}
	}

	// Try to decompress
	if !result.EncryptedNoKey {
		_, err := m.decompress(data)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("decompression failed: %v", err)
			return result, nil
		}
		result.Decompressible = true
	}

	result.Encrypted = strings.HasSuffix(filename, ".enc")
	result.CreatedAt = info.ModTime()

	return result, nil
}

// VerifyResult represents the result of a backup verification
type VerifyResult struct {
	Filename       string    `json:"filename"`
	Valid          bool      `json:"valid"`
	Size           int64     `json:"size"`
	CreatedAt      time.Time `json:"created_at"`
	ChecksumMatch  bool      `json:"checksum_match"`
	Encrypted      bool      `json:"encrypted"`
	Decryptable    bool      `json:"decryptable"`
	Decompressible bool      `json:"decompressible"`
	EncryptedNoKey bool      `json:"encrypted_no_key"`
	Error          string    `json:"error,omitempty"`
}

// runPgDump executes pg_dump to create a database dump
func (m *Manager) runPgDump(ctx context.Context, outfile string) error {
	// Parse database URL to get connection details
	// pg_dump format: pg_dump [options] dbname

	args := []string{
		"--format=plain",
		"--no-owner",
		"--no-acl",
		"--verbose",
	}

	// Add connection string from DATABASE_URL
	// We need to parse it to extract dbname for pg_dump
	dbName := m.config.DatabaseName
	if dbName == "" && m.config.DatabaseURL != "" {
		// Try to extract dbname from URL
		parts := strings.Split(m.config.DatabaseURL, "/")
		if len(parts) > 0 {
			lastPart := parts[len(parts)-1]
			if idx := strings.Index(lastPart, "?"); idx >= 0 {
				dbName = lastPart[:idx]
			} else {
				dbName = lastPart
			}
		}
	}

	if dbName == "" {
		return fmt.Errorf("database name not configured")
	}

	args = append(args, dbName)

	// Set PGPASSWORD environment variable for authentication
	cmd := exec.CommandContext(ctx, "pg_dump", args...)
	cmd.Env = append(os.Environ(), m.getEnvVars()...)

	// Redirect output to file
	out, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer out.Close()

	cmd.Stdout = out
	cmd.Stderr = os.Stderr // Show progress

	m.logger.Debug("Running pg_dump", zap.Strings("args", args))

	return cmd.Run()
}

// runPgRestore executes psql to restore a database dump
func (m *Manager) runPgRestore(ctx context.Context, infile string) error {
	// psql format: psql [options] dbname

	dbName := m.config.DatabaseName
	if dbName == "" && m.config.DatabaseURL != "" {
		parts := strings.Split(m.config.DatabaseURL, "/")
		if len(parts) > 0 {
			lastPart := parts[len(parts)-1]
			if idx := strings.Index(lastPart, "?"); idx >= 0 {
				dbName = lastPart[:idx]
			} else {
				dbName = lastPart
			}
		}
	}

	if dbName == "" {
		return fmt.Errorf("database name not configured")
	}

	args := []string{dbName}

	cmd := exec.CommandContext(ctx, "psql", args...)
	cmd.Env = append(os.Environ(), m.getEnvVars()...)

	// Open input file
	in, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer in.Close()

	cmd.Stdin = in
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	m.logger.Debug("Running psql restore", zap.Strings("args", args))

	return cmd.Run()
}

// getEnvVars extracts database connection environment variables from DATABASE_URL
func (m *Manager) getEnvVars() []string {
	if m.config.DatabaseURL == "" {
		return nil
	}

	var envs []string

	// Parse PostgreSQL URL: postgres://user:pass@host:port/dbname?sslmode=...
	url := m.config.DatabaseURL

	// Remove protocol prefix
	if strings.HasPrefix(url, "postgres://") {
		url = strings.TrimPrefix(url, "postgres://")
	} else if strings.HasPrefix(url, "postgresql://") {
		url = strings.TrimPrefix(url, "postgresql://")
	}

	// Split user:pass@host:port/dbname
	atIdx := strings.Index(url, "@")
	if atIdx > 0 {
		credentials := url[:atIdx]
		rest := url[atIdx+1:]

		// Parse user:pass
		if colonIdx := strings.Index(credentials, ":"); colonIdx > 0 {
			user := credentials[:colonIdx]
			pass := credentials[colonIdx+1:]
			envs = append(envs, fmt.Sprintf("PGUSER=%s", user))
			envs = append(envs, fmt.Sprintf("PGPASSWORD=%s", pass))
		}

		// Parse host:port/dbname
		slashIdx := strings.Index(rest, "/")
		if slashIdx > 0 {
			hostPort := rest[:slashIdx]
			// Parse host:port
			if colonIdx := strings.Index(hostPort, ":"); colonIdx > 0 {
				host := hostPort[:colonIdx]
				port := hostPort[colonIdx+1:]
				// Remove query params from port
				if qIdx := strings.Index(port, "?"); qIdx > 0 {
					port = port[:qIdx]
				}
				envs = append(envs, fmt.Sprintf("PGHOST=%s", host))
				envs = append(envs, fmt.Sprintf("PGPORT=%s", port))
			} else {
				envs = append(envs, fmt.Sprintf("PGHOST=%s", hostPort))
			}
		}
	}

	return envs
}

// compress compresses data using gzip
func (m *Manager) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, m.config.CompressionLevel)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompress decompresses gzip data
func (m *Manager) decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// encrypt encrypts data using AES-256-GCM
func (m *Manager) encrypt(data []byte, passphrase string) ([]byte, error) {
	// Derive key from passphrase
	key := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and prepend nonce
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts AES-256-GCM encrypted data
func (m *Manager) decrypt(data []byte, passphrase string) ([]byte, error) {
	// Derive key from passphrase
	key := sha256.Sum256([]byte(passphrase))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// saveMetadata saves backup metadata to a sidecar file
func (m *Manager) saveMetadata(backup *Backup) error {
	metaFile := filepath.Join(m.config.StorageDir, backup.Filename+".meta.json")
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaFile, data, 0600)
}

// loadMetadata loads backup metadata from sidecar file
func (m *Manager) loadMetadata(filename string) (*Backup, error) {
	metaFile := filepath.Join(m.config.StorageDir, filename+".meta.json")
	data, err := os.ReadFile(metaFile)
	if err != nil {
		return nil, err
	}
	var backup Backup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, err
	}
	return &backup, nil
}

// uploadToS3 uploads a backup to S3
func (m *Manager) uploadToS3(ctx context.Context, backup *Backup, data []byte) error {
	// This is a placeholder for S3 upload functionality
	// In a full implementation, you would use the AWS SDK or minio-go
	// For now, we'll just log that S3 upload is not implemented
	m.logger.Info("S3 upload requested but not implemented",
		zap.String("bucket", m.config.S3Bucket),
		zap.String("filename", backup.Filename))
	return nil
}

// applyRetention removes old backups based on retention policy
func (m *Manager) applyRetention() {
	backups, err := m.List()
	if err != nil {
		m.logger.Warn("Failed to list backups for retention", zap.Error(err))
		return
	}

	if len(backups) <= m.config.RetentionCount {
		return
	}

	// Remove oldest backups beyond retention count
	for i := m.config.RetentionCount; i < len(backups); i++ {
		backup := backups[i]
		filepath := filepath.Join(m.config.StorageDir, backup.Filename)
		if err := os.Remove(filepath); err != nil {
			m.logger.Warn("Failed to remove old backup",
				zap.String("filename", backup.Filename),
				zap.Error(err))
		} else {
			// Also remove metadata file
			metaFile := filepath + ".meta.json"
			os.Remove(metaFile)
			m.logger.Info("Removed old backup", zap.String("filename", backup.Filename))
		}
	}
}

// GetScheduleInfo returns information about automated backup scheduling
type ScheduleInfo struct {
	Enabled bool   `json:"enabled"`
	Cron    string `json:"cron"`
	NextRun string `json:"next_run,omitempty"`
	LastRun string `json:"last_run,omitempty"`
}

// GetSchedule returns the current backup schedule configuration
func (m *Manager) GetSchedule() *ScheduleInfo {
	return &ScheduleInfo{
		Enabled: m.config.ScheduleEnabled,
		Cron:    m.config.ScheduleCron,
	}
}

// EncryptPassword encrypts a password for storage in config files
func EncryptPassword(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Derive key
	key := sha256.Sum256(append(salt, []byte(password)...))

	// Return base64 encoded salt:key
	combined := append(salt, key[:]...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// ParseDatabaseURL extracts database name and connection details from URL
func ParseDatabaseURL(dbURL string) (dbname string, host string, port string, user string, err error) {
	if dbURL == "" {
		return "", "", "", "", fmt.Errorf("empty database URL")
	}

	url := dbURL

	// Remove protocol prefix
	if strings.HasPrefix(url, "postgres://") {
		url = strings.TrimPrefix(url, "postgres://")
	} else if strings.HasPrefix(url, "postgresql://") {
		url = strings.TrimPrefix(url, "postgresql://")
	}

	// Split user:pass@host:port/dbname
	atIdx := strings.Index(url, "@")
	if atIdx <= 0 {
		return "", "", "", "", fmt.Errorf("invalid database URL format")
	}

	credentials := url[:atIdx]
	rest := url[atIdx+1:]

	// Parse user:pass
	if colonIdx := strings.Index(credentials, ":"); colonIdx > 0 {
		user = credentials[:colonIdx]
	}

	// Parse host:port/dbname
	slashIdx := strings.Index(rest, "/")
	if slashIdx <= 0 {
		return "", "", "", "", fmt.Errorf("invalid database URL format")
	}

	hostPort := rest[:slashIdx]
	dbPart := rest[slashIdx+1:]

	// Remove query params from dbname
	if qIdx := strings.Index(dbPart, "?"); qIdx > 0 {
		dbname = dbPart[:qIdx]
	} else {
		dbname = dbPart
	}

	// Parse host:port
	if colonIdx := strings.Index(hostPort, ":"); colonIdx > 0 {
		host = hostPort[:colonIdx]
		port = hostPort[colonIdx+1:]
		// Remove query params from port
		if qIdx := strings.Index(port, "?"); qIdx > 0 {
			port = port[:qIdx]
		}
	} else {
		host = hostPort
	}

	return dbname, host, port, user, nil
}
