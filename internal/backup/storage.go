// Package backup provides storage abstractions for database backups
package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// A Storage interface and a LocalStorage implementing it stood here, and
// docs/PRODUCTION-READINESS.md said Manager "routes through the Storage
// interface; both LocalStorage and S3Storage are wired". It did not. Manager
// reads and writes local backups with plain os.ReadFile / os.WriteFile against
// config.StorageDir, and reaches S3 through the concrete *S3Storage below -- so
// LocalStorage was never constructed by anything, and the interface had no
// reference outside its own declaration.
//
// S3 itself works: a created backup is uploaded through S3Storage.Save, and a
// restore falls back to S3Storage.Load when the file is not on disk. What was
// untrue was the architecture, not the capability, so the document is corrected
// rather than the code bent to match a design nobody adopted.

// S3Storage stores backups in an S3-compatible bucket.
type S3Storage struct {
	bucket    string
	region    string
	endpoint  string
	accessKey string
	secretKey string
	prefix    string // Optional prefix for all keys
}

// NewS3Storage creates a new S3 storage backend
func NewS3Storage(bucket, region, endpoint, accessKey, secretKey, prefix string) *S3Storage {
	return &S3Storage{
		bucket:    bucket,
		region:    region,
		endpoint:  endpoint,
		accessKey: accessKey,
		secretKey: secretKey,
		prefix:    prefix,
	}
}

// Save stores a backup to S3
func (s *S3Storage) Save(ctx context.Context, name string, data []byte) (string, error) {
	key := s.key(name)
	reqURL := s.objectURL(key)

	req, err := http.NewRequestWithContext(ctx, "PUT", reqURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create S3 PUT request: %w", err)
	}

	s.signRequest(req, data)

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("S3 PUT request failed: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("S3 PUT returned status %d", resp.StatusCode)
	}

	return "s3://" + s.bucket + "/" + key, nil
}

// Load retrieves a backup from S3
func (s *S3Storage) Load(ctx context.Context, name string) ([]byte, error) {
	key := s.key(name)
	reqURL := s.objectURL(key)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 GET request: %w", err)
	}

	s.signRequest(req, nil)

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("S3 GET request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("S3 GET returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Delete removes a backup from S3
func (s *S3Storage) Delete(ctx context.Context, name string) error {
	key := s.key(name)
	reqURL := s.objectURL(key)

	req, err := http.NewRequestWithContext(ctx, "DELETE", reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create S3 DELETE request: %w", err)
	}

	s.signRequest(req, nil)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 DELETE request failed: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("S3 DELETE returned status %d", resp.StatusCode)
	}

	return nil
}

// listBucketResult represents the XML response from S3 ListObjectsV2
type listBucketResult struct {
	XMLName  xml.Name   `xml:"ListBucketResult"`
	Contents []s3Object `xml:"Contents"`
}

type s3Object struct {
	Key          string    `xml:"Key"`
	LastModified time.Time `xml:"LastModified"`
	Size         int64     `xml:"Size"`
}

// List returns all backups in the S3 bucket
func (s *S3Storage) List(ctx context.Context) ([]*Backup, error) {
	baseURL := s.bucketURL()
	query := "?list-type=2"
	if s.prefix != "" {
		query += "&prefix=" + s.prefix + "/"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 LIST request: %w", err)
	}

	s.signRequest(req, nil)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("S3 LIST request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("S3 LIST returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read S3 LIST response: %w", err)
	}

	var result listBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse S3 LIST response: %w", err)
	}

	var backups []*Backup
	for _, obj := range result.Contents {
		// Strip prefix to get the filename
		filename := obj.Key
		if s.prefix != "" && strings.HasPrefix(filename, s.prefix+"/") {
			filename = filename[len(s.prefix)+1:]
		}

		if filename == "" {
			continue
		}

		// Skip metadata files
		if hasSuffix(filename, ".meta.json") {
			continue
		}

		if !isBackupFile(filename) {
			continue
		}

		backup := &Backup{
			Filename:  filename,
			Name:      extractBackupName(filename),
			CreatedAt: obj.LastModified,
			Size:      obj.Size,
			Encrypted: hasSuffix(filename, ".enc"),
			Storage:   "s3",
		}
		backups = append(backups, backup)
	}

	return backups, nil
}

// Exists checks if a backup exists in S3
func (s *S3Storage) Exists(ctx context.Context, name string) (bool, error) {
	key := s.key(name)
	reqURL := s.objectURL(key)

	req, err := http.NewRequestWithContext(ctx, "HEAD", reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create S3 HEAD request: %w", err)
	}

	s.signRequest(req, nil)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("S3 HEAD request failed: %w", err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("S3 HEAD returned status %d", resp.StatusCode)
	}

	return true, nil
}

// bucketURL returns the base URL for the S3 bucket
func (s *S3Storage) bucketURL() string {
	if s.endpoint != "" {
		return strings.TrimRight(s.endpoint, "/") + "/" + s.bucket
	}
	return "https://" + s.bucket + ".s3." + s.region + ".amazonaws.com"
}

// objectURL returns the full URL for an S3 object
func (s *S3Storage) objectURL(key string) string {
	return s.bucketURL() + "/" + key
}

// signRequest signs an HTTP request using AWS Signature Version 4
func (s *S3Storage) signRequest(req *http.Request, payload []byte) {
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	// Compute payload hash
	var payloadHash string
	if payload != nil {
		h := sha256.Sum256(payload)
		payloadHash = hex.EncodeToString(h[:])
	} else {
		h := sha256.Sum256([]byte(""))
		payloadHash = hex.EncodeToString(h[:])
	}

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if payload != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	host := req.URL.Host
	req.Header.Set("Host", host)

	// Build canonical headers (sorted)
	signedHeaderKeys := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeaderKeys)
	signedHeaders := strings.Join(signedHeaderKeys, ";")

	var canonicalHeaders strings.Builder
	for _, key := range signedHeaderKeys {
		var val string
		switch key {
		case "host":
			val = host
		default:
			val = req.Header.Get(key)
		}
		canonicalHeaders.WriteString(key + ":" + strings.TrimSpace(val) + "\n")
	}

	// Build canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := req.URL.RawQuery

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	// Build string to sign
	credentialScope := datestamp + "/" + s.region + "/s3/aws4_request"
	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credentialScope + "\n" + hex.EncodeToString(crHash[:])

	// Derive signing key
	signingKey := s.deriveSigningKey(datestamp)

	// Compute signature
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Set Authorization header
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
}

// deriveSigningKey derives the AWS V4 signing key
func (s *S3Storage) deriveSigningKey(datestamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+s.secretKey), []byte(datestamp))
	kRegion := hmacSHA256(kDate, []byte(s.region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}

// hmacSHA256 computes HMAC-SHA256
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// URL returns an S3 URL for the backup
func (s *S3Storage) URL(name string) string {
	key := s.key(name)
	if s.endpoint != "" {
		return s.endpoint + "/" + s.bucket + "/" + key
	}
	return "s3://" + s.bucket + "/" + key
}

// key returns the full S3 key for a backup name
func (s *S3Storage) key(name string) string {
	if s.prefix != "" {
		return s.prefix + "/" + name
	}
	return name
}

// A progress-tracking Reader and its Progress (bytes per second, percent
// complete, ETA) stood here, for a caller that would stream a backup through
// them. Nothing did. Deleted with LocalStorage.

// Common errors
var (
	ErrNotFound       = &BackupError{Code: "NOT_FOUND", Message: "backup not found"}
	ErrChecksum       = &BackupError{Code: "CHECKSUM", Message: "checksum verification failed"}
	ErrEncryption     = &BackupError{Code: "ENCRYPTION", Message: "encryption/decryption failed"}
	ErrNotImplemented = &BackupError{Code: "NOT_IMPLEMENTED", Message: "feature not implemented"}
)

// BackupError represents a backup-related error
type BackupError struct {
	Code    string
	Message string
	Err     error
}

// Error returns the error message
func (e *BackupError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Message + ": " + e.Err.Error()
	}
	return e.Code + ": " + e.Message
}

// Unwrap returns the underlying error
func (e *BackupError) Unwrap() error {
	return e.Err
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func isBackupFile(name string) bool {
	return hasSuffix(name, ".sql.gz") || hasSuffix(name, ".sql.gz.enc") || hasPrefix(name, "backup_")
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func extractBackupName(filename string) string {
	name := filename
	name = trimSuffix(name, ".sql.gz.enc")
	name = trimSuffix(name, ".sql.gz")
	name = trimSuffix(name, ".enc")
	return name
}

func trimSuffix(s, suffix string) string {
	if hasSuffix(s, suffix) {
		return s[:len(s)-len(suffix)]
	}
	return s
}

// A DirEntry/FileInfo interface pair, five wrapper functions over them, five
// more os-level wrappers underneath, and the package-level os function vars the
// tests substituted, all stood here. Every one of them existed so LocalStorage
// could list a directory against a fake filesystem. With LocalStorage gone
// nothing reads a directory in this package: S3Storage lists a bucket over
// HTTP, and Manager touches the local backup directory with os.* directly.
//
// dirEntry and fileInfo were os.DirEntry / os.FileInfo shims LocalStorage.List
// built while walking the backup directory. Deleted with it.
