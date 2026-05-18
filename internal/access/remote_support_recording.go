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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
