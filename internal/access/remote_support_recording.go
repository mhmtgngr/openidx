// Package access — remote-support session recording upload pipeline.
//
// The admin browser uses MediaRecorder to capture the inbound WebRTC video
// stream, then streams chunks (typically every 5 s) to the access service.
// We append each chunk byte-for-byte to a per-session WebM file on local
// disk; each MediaRecorder timeslice yields a standalone WebM segment that
// concatenates into a playable file with no remuxing required.
//
// Storage is local-filesystem in this iteration. The handler talks through
// `recordingStore` so a future S3 / GCS backend can swap in without
// changing the HTTP surface.
package access

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

// recordingStore is the storage backend the recording handlers talk to.
// Decoupled so a non-filesystem backend (S3, etc.) drops in later.
type recordingStore interface {
	// Append writes the chunk bytes to the recording for sessionID at the
	// supplied chunk index. Index is monotonically increasing and used
	// only for ordering — Append doesn't have to materialize per-chunk
	// files. Returns the number of bytes written.
	Append(sessionID string, chunkIndex int, body io.Reader) (int64, error)
	// Open returns a reader for the assembled recording.
	Open(sessionID string) (io.ReadCloser, int64, error)
	// Key returns the storage key (relative path) of the recording, used
	// to populate recording_storage_key.
	Key(sessionID string) string
	// Delete removes every byte the store holds for this session. Used
	// by the retention sweeper to purge expired recordings without
	// dropping the audit row in remote_support_sessions. Idempotent — a
	// missing session must succeed.
	Delete(sessionID string) error
}

// filesystemRecordingStore writes per-session WebM files under a root
// directory. Concurrent appends to the same session are serialized via
// OS append-mode opens.
type filesystemRecordingStore struct {
	root string
}

func newFilesystemRecordingStore(root string) (*filesystemRecordingStore, error) {
	if root == "" {
		return nil, errors.New("recordings root path required")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create recordings root: %w", err)
	}
	return &filesystemRecordingStore{root: root}, nil
}

func (s *filesystemRecordingStore) path(sessionID string) string {
	// session IDs are UUIDs; we still sanitize defensively so a future
	// callsite can't slip a "../" into the filename.
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '_'
	}, sessionID)
	return filepath.Join(s.root, safe, "recording.webm")
}

func (s *filesystemRecordingStore) Key(sessionID string) string {
	return filepath.Join(filepath.Base(s.root), sessionID, "recording.webm")
}

func (s *filesystemRecordingStore) Append(sessionID string, _ int, body io.Reader) (int64, error) {
	full := s.path(sessionID)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(full, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(f, body)
}

func (s *filesystemRecordingStore) Open(sessionID string) (io.ReadCloser, int64, error) {
	full := s.path(sessionID)
	fi, err := os.Stat(full)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// Delete drops the per-session directory and everything below it.
// Idempotent: a missing session-dir is treated as a successful delete
// because the retention sweeper may retry against rows whose blob was
// already cleaned up by an out-of-band process.
func (s *filesystemRecordingStore) Delete(sessionID string) error {
	dir := filepath.Dir(s.path(sessionID))
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// s3RecordingStore stores each MediaRecorder chunk as a discrete S3
// object under "<prefix>/<session_id>/<NNNNNN>.webm". On Open the
// store lists the chunks, sorts by their zero-padded numeric prefix,
// and returns a sequential reader that concatenates them. Because
// MediaRecorder timeslice output is a valid WebM segment per chunk,
// the concatenation is byte-for-byte playable without remuxing.
//
// We pick per-chunk objects rather than multipart upload because the
// chunk sizes WebRTC produces (~300 KB – 1.25 MB at typical screen-
// recording bitrates) are below S3's 5 MB minimum part size. Buffering
// to hit that minimum would add server-side memory pressure with no
// downstream benefit — separate objects are cheap on S3.
type s3RecordingStore struct {
	client *minio.Client
	bucket string
	prefix string // optional path prefix inside the bucket
}

func newS3RecordingStore(cfg s3RecordingConfig) (*s3RecordingStore, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, errors.New("s3 recording store requires endpoint and bucket")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("s3 recording store requires access key and secret")
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("init minio client: %w", err)
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	return &s3RecordingStore{client: client, bucket: cfg.Bucket, prefix: prefix}, nil
}

// s3RecordingConfig is the parsed configuration for the S3 store, kept
// separate so the public NewS3RecordingStore stays narrow.
type s3RecordingConfig struct {
	Endpoint        string
	Bucket          string
	Region          string
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string
	UseSSL          bool
}

func (s *s3RecordingStore) objectKey(sessionID string, chunkIndex int) string {
	// %06d gives us natural sort order up to a million chunks (~ 57
	// days at one chunk every 5 s — far past any realistic session).
	name := fmt.Sprintf("%06d.webm", chunkIndex)
	return path.Join(s.prefix, sanitizeKeyComponent(sessionID), name)
}

func (s *s3RecordingStore) sessionPrefix(sessionID string) string {
	return path.Join(s.prefix, sanitizeKeyComponent(sessionID)) + "/"
}

func (s *s3RecordingStore) Key(sessionID string) string {
	return path.Join(s.prefix, sessionID) + "/"
}

func (s *s3RecordingStore) Append(sessionID string, chunkIndex int, body io.Reader) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Stream the chunk directly; -1 size tells minio-go to autodetect
	// via multipart, which is fine even for sub-5MB chunks because we
	// only ever upload a single part per object.
	info, err := s.client.PutObject(
		ctx, s.bucket, s.objectKey(sessionID, chunkIndex), body, -1,
		minio.PutObjectOptions{ContentType: "video/webm"},
	)
	if err != nil {
		return 0, err
	}
	return info.Size, nil
}

func (s *s3RecordingStore) Open(sessionID string) (io.ReadCloser, int64, error) {
	ctx := context.Background()
	objects := s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:    s.sessionPrefix(sessionID),
		Recursive: false,
	})
	type chunkRef struct {
		key  string
		size int64
	}
	chunks := make([]chunkRef, 0, 16)
	for obj := range objects {
		if obj.Err != nil {
			return nil, 0, obj.Err
		}
		// Filter to chunks belonging to this session (defense in depth
		// against accidental sibling prefixes).
		if !strings.HasSuffix(obj.Key, ".webm") {
			continue
		}
		chunks = append(chunks, chunkRef{key: obj.Key, size: obj.Size})
	}
	if len(chunks) == 0 {
		return nil, 0, fmt.Errorf("no recording chunks for session %s", sessionID)
	}
	// ListObjects already returns lexically-sorted keys; the %06d
	// padding makes lex order match numeric order. Sort defensively
	// in case a future minio-go version changes the iteration guarantee.
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].key < chunks[j].key })

	total := int64(0)
	keys := make([]string, len(chunks))
	for i, c := range chunks {
		total += c.size
		keys[i] = c.key
	}

	return &s3ConcatenatingReader{client: s.client, bucket: s.bucket, keys: keys}, total, nil
}

// Delete removes every chunk object under the session's prefix. Uses
// minio-go's bulk-remove channel so we issue one DELETE per chunk in
// parallel; idempotent on missing objects.
func (s *s3RecordingStore) Delete(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	objects := s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:    s.sessionPrefix(sessionID),
		Recursive: false,
	})
	toRemove := make(chan minio.ObjectInfo)
	go func() {
		defer close(toRemove)
		for obj := range objects {
			if obj.Err != nil {
				continue
			}
			toRemove <- obj
		}
	}()
	for rmErr := range s.client.RemoveObjects(ctx, s.bucket, toRemove, minio.RemoveObjectsOptions{}) {
		if rmErr.Err != nil {
			return fmt.Errorf("remove %s: %w", rmErr.ObjectName, rmErr.Err)
		}
	}
	return nil
}

// s3ConcatenatingReader streams the per-chunk S3 objects one after the
// other so the caller sees a single Reader. Closes the underlying GET
// connection between objects to keep socket use bounded.
type s3ConcatenatingReader struct {
	client *minio.Client
	bucket string
	keys   []string
	idx    int
	cur    *minio.Object
}

func (r *s3ConcatenatingReader) Read(p []byte) (int, error) {
	for {
		if r.cur == nil {
			if r.idx >= len(r.keys) {
				return 0, io.EOF
			}
			obj, err := r.client.GetObject(context.Background(), r.bucket, r.keys[r.idx], minio.GetObjectOptions{})
			if err != nil {
				return 0, err
			}
			r.cur = obj
		}
		n, err := r.cur.Read(p)
		if n > 0 {
			return n, nil
		}
		if errors.Is(err, io.EOF) {
			_ = r.cur.Close()
			r.cur = nil
			r.idx++
			continue
		}
		return 0, err
	}
}

func (r *s3ConcatenatingReader) Close() error {
	if r.cur != nil {
		err := r.cur.Close()
		r.cur = nil
		return err
	}
	return nil
}

// sanitizeKeyComponent strips path traversal bait from a string before
// it becomes part of an object key. Session IDs are UUIDs so this is
// defense in depth, not the primary protection.
func sanitizeKeyComponent(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '_'
	}, s)
}

// SetRecordingStore installs the storage backend used by the upload /
// download / finalize handlers. Optional — when nil the endpoints
// respond 503 so the admin viewer can surface a clear "recording not
// configured" message instead of timing out.
func (h *RemoteSupportHandler) SetRecordingStore(s recordingStore) {
	h.recordingStore = s
}

// recordingPath constants — the chunk size limit is generous (50 MiB)
// because adaptive bitrate can produce big keyframe chunks; the cap is
// purely a safety net against an upload buffer claiming infinite memory.
const maxRecordingChunkBytes int64 = 50 * 1024 * 1024

// HandleUploadRecordingChunk appends one MediaRecorder chunk to the
// session's recording. Called from the admin viewer's MediaRecorder
// ondataavailable handler. Chunks must be uploaded in order; the handler
// trusts the X-Chunk-Index header for ordering metadata but doesn't
// reorder out-of-band uploads.
func (h *RemoteSupportHandler) HandleUploadRecordingChunk(c *gin.Context) {
	if h.recordingStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "recording not configured"})
		return
	}
	sessionID := c.Param("id")
	row, err := h.fetchSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	if !row.RecordingEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "recording not enabled for this session"})
		return
	}
	chunkIndex, _ := strconv.Atoi(c.GetHeader("X-Chunk-Index"))

	// Cap the request body so a runaway browser doesn't fill disk.
	body := http.MaxBytesReader(c.Writer, c.Request.Body, maxRecordingChunkBytes)
	defer body.Close()

	written, err := h.recordingStore.Append(sessionID, chunkIndex, body)
	if err != nil {
		h.logger.Warn("HandleUploadRecordingChunk: append failed",
			zap.String("session_id", sessionID), zap.Int("chunk", chunkIndex), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "append failed"})
		return
	}

	// Update tallies. Best-effort — a missed UPDATE doesn't lose data,
	// just the accounting (which the finalize step will reconcile from
	// the file size when needed).
	if h.db != nil && h.db.Pool != nil {
		_, _ = h.db.Pool.Exec(c.Request.Context(), `
            UPDATE remote_support_sessions
               SET recording_size_bytes = recording_size_bytes + $2,
                   recording_chunk_count = recording_chunk_count + 1,
                   recording_storage_key = COALESCE(recording_storage_key, $3),
                   last_activity_at = NOW()
             WHERE id = $1
        `, sessionID, written, h.recordingStore.Key(sessionID))
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status":      "accepted",
		"chunk_index": chunkIndex,
		"size":        written,
	})
}

// HandleFinalizeRecording is called once the admin viewer's MediaRecorder
// emits its final chunk and stops. Stamps recording_finalized_at and
// derives recording_url (relative to the access service's public base).
func (h *RemoteSupportHandler) HandleFinalizeRecording(c *gin.Context) {
	if h.recordingStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "recording not configured"})
		return
	}
	sessionID := c.Param("id")
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	publicURL := fmt.Sprintf("/api/v1/access/remote-support/sessions/%s/recording", sessionID)
	_, err := h.db.Pool.Exec(c.Request.Context(), `
        UPDATE remote_support_sessions
           SET recording_finalized_at = NOW(),
               recording_url = $2
         WHERE id = $1
    `, sessionID, publicURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "finalize failed"})
		return
	}
	h.audit(c.Request.Context(), "remote_support.recording_finalized", sessionID, "success", "")
	c.JSON(http.StatusOK, gin.H{
		"status":        "finalized",
		"recording_url": publicURL,
		"finalized_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

// HandleDownloadRecording streams the assembled WebM back. Mounted on the
// auth-protected admin group; downstream this should grow scoping checks
// (the requester must be an admin in the agent's tenant) once tenant
// boundaries are enforced on this surface.
func (h *RemoteSupportHandler) HandleDownloadRecording(c *gin.Context) {
	if h.recordingStore == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "recording not configured"})
		return
	}
	sessionID := c.Param("id")
	reader, size, err := h.recordingStore.Open(sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recording not found"})
		return
	}
	defer reader.Close()

	filename := "openidx-recording-" + sessionID + ".webm"
	c.Header("Content-Type", "video/webm")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Header("Content-Length", strconv.FormatInt(size, 10))
	if _, err := io.Copy(c.Writer, reader); err != nil {
		h.logger.Warn("HandleDownloadRecording: copy failed",
			zap.String("session_id", sessionID), zap.Error(err))
	}
}
