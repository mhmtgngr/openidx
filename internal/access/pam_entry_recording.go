// Package access — sealing and purging PAM entry session recordings.
//
// guacd records a PAM entry session to pam_entry_sessions.recording_path. The
// recording sealer and the retention purge (guac_recording_sealer.go,
// remote_support_retention.go) read only guacamole_sessions, the route path's
// table, so an entry session's recording stayed plaintext on disk and was
// never purged (migration 241). These sweeps run beside them on the same tick
// and reuse the same seal (sealOneGuacRecording: one descriptor, refusal of
// ciphertext, atomic rename) and the same path guard.
//
// A route launch writes a row in both tables for one file. Those rows are
// left to the route path, which seals and purges them already: the entry
// sweeps select only recordings no guacamole_sessions row names.
//
// Entry sessions have no legal-hold table (guacamole_recording_legal_holds
// references guacamole_sessions), so nothing here can be held from purge.
package access

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// sealPamEntryRecordings encrypts at rest every ended entry session recording
// that is still plaintext. Inert unless a keyring is configured, as the route
// path's sealer is.
func (h *RemoteSupportHandler) sealPamEntryRecordings(ctx context.Context) {
	if h.guacRecordingRing == nil || !h.guacRecordingRing.Enabled() || h.db == nil || h.db.Pool == nil {
		return
	}
	//orgscope:ignore background cross-org sweep under bypass-RLS; org_id selected per row and used to scope the write
	rows, err := h.db.Pool.Query(ctx, `
		SELECT s.id::text, s.org_id::text, s.recording_path
		  FROM pam_entry_sessions s
		 WHERE s.status <> 'active'
		   AND COALESCE(s.recording_path, '') <> ''
		   AND s.recording_sealed_at IS NULL
		   AND s.recording_purged_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM guacamole_sessions g WHERE g.recording_path = s.recording_path)
		 ORDER BY s.ended_at NULLS FIRST
		 LIMIT 50`)
	if err != nil {
		h.logger.Warn("sealPamEntryRecordings: query failed", zap.Error(err))
		return
	}
	type job struct{ id, orgID, path string }
	var jobs []job
	for rows.Next() {
		var j job
		if rows.Scan(&j.id, &j.orgID, &j.path) == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()

	sealed := 0
	for _, j := range jobs {
		if !h.guacRecordingPathSafe(j.path) {
			h.logger.Warn("sealPamEntryRecordings: skipping unsafe recording_path", zap.String("session_id", j.id))
			continue
		}
		if _, statErr := os.Stat(j.path); statErr != nil {
			continue // not on disk (yet); a later tick tries again
		}
		sum, keyID, sealErr := h.sealOneGuacRecording(j.path)
		if errors.Is(sealErr, errAlreadySealed) {
			h.logger.Warn("sealPamEntryRecordings: recording is already ciphertext but the row carries no seal metadata; refusing to encrypt it twice",
				zap.String("session_id", j.id))
			continue
		}
		if sealErr != nil {
			h.logger.Warn("sealPamEntryRecordings: seal failed", zap.String("session_id", j.id), zap.Error(sealErr))
			continue
		}
		claimed, execErr := h.recordPamEntrySeal(ctx, j.id, j.orgID, sum, keyID)
		if execErr != nil {
			h.logger.Error("sealPamEntryRecordings: sealed bytes but metadata write FAILED; manual reconciliation needed",
				zap.String("session_id", j.id), zap.Error(execErr))
			continue
		}
		if claimed {
			sealed++
		}
	}
	if sealed > 0 {
		h.logger.Info("sealPamEntryRecordings: sealed recordings", zap.Int("count", sealed))
	}
}

// recordPamEntrySeal stamps the seal and is the claim: only the replica whose
// write lands announces it (see recordGuacSeal).
func (h *RemoteSupportHandler) recordPamEntrySeal(ctx context.Context, sessionID, orgID, sum string, keyID byte) (bool, error) {
	//orgscope:ignore background sweep; row identified by PK, org fixed at insert
	tag, err := h.db.Pool.Exec(ctx, `
		UPDATE pam_entry_sessions
		   SET recording_sealed_at = NOW(), recording_sha256 = $1, recording_key_id = $2
		 WHERE id = $3 AND recording_sealed_at IS NULL`, sum, int(keyID), sessionID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	details := fmt.Sprintf(`{"session_id":%q,"sha256":%q,"key_id":%d,"path":"entry"}`, sessionID, sum, int(keyID))
	//orgscope:ignore audit_events stamped with the session's own org_id; background sweep has no request org
	if _, aerr := h.db.Pool.Exec(ctx, `
		INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, target_type, resource_id, details, created_at, org_id)
		VALUES (gen_random_uuid(), 'pam.recording.sealed', 'privileged_access', 'recording.seal', 'success', 'system', 'pam_entry_session', $1, $2, NOW(), NULLIF($3,'')::uuid)`,
		sessionID, details, orgID); aerr != nil {
		h.logger.Warn("recordPamEntrySeal: audit insert failed", zap.Error(aerr))
	}
	return true, nil
}

// sweepExpiredPamEntryRecordings removes entry session recordings past their
// organization's retention and stamps recording_purged_at.
func (h *RemoteSupportHandler) sweepExpiredPamEntryRecordings(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	//orgscope:ignore background retention sweep, cross-org by design under bypass-RLS; each row's own org resolves its retention
	rows, err := h.db.Pool.Query(ctx, `
		SELECT s.id::text, s.org_id::text, s.recording_path, COALESCE(s.ended_at, s.started_at)
		  FROM pam_entry_sessions s
		 WHERE s.status <> 'active'
		   AND COALESCE(s.recording_path, '') <> ''
		   AND s.recording_purged_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM guacamole_sessions g WHERE g.recording_path = s.recording_path)`)
	if err != nil {
		h.logger.Warn("sweepExpiredPamEntryRecordings: query failed", zap.Error(err))
		return
	}
	type cand struct {
		id, orgID, path string
		endedAt         time.Time
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if rows.Scan(&c.id, &c.orgID, &c.path, &c.endedAt) == nil {
			cands = append(cands, c)
		}
	}
	rows.Close()

	now := time.Now().UTC()
	purged := 0
	for _, c := range cands {
		ret := h.resolveEffectiveRetention(ctx, nil, c.orgID)
		if ret <= 0 || int(now.Sub(c.endedAt).Hours()/24) < ret {
			continue
		}
		if !h.removeGuacRecordingFiles(c.id, c.path) {
			continue
		}
		if _, err := h.db.Pool.Exec(ctx,
			`UPDATE pam_entry_sessions SET recording_purged_at = NOW()
			  WHERE id = $1 AND org_id = $2::uuid AND recording_purged_at IS NULL`, c.id, c.orgID); err != nil {
			h.logger.Warn("sweepExpiredPamEntryRecordings: marking the purge failed", zap.String("session_id", c.id), zap.Error(err))
			continue
		}
		h.audit(ctx, "pam.recording_purged", c.id, "enforced", "")
		purged++
	}
	if purged > 0 {
		h.logger.Info("PAM entry recording sweep complete", zap.Int("purged", purged))
	}
}

// removeGuacRecordingFiles deletes a recording and its transcript when the
// path is strictly inside the recordings root. It reports whether the files
// are gone; an unsafe path is refused, logged and left alone, so the row is
// not marked purged over a file that still exists.
func (h *RemoteSupportHandler) removeGuacRecordingFiles(sessionID, path string) bool {
	root := h.guacRecordingsRoot
	if root == "" || !isUnderRoot(path, root) {
		h.logger.Warn("PAM recording purge: skipping unsafe recording_path",
			zap.String("session_id", sessionID), zap.String("recording_path", path))
		return false
	}
	if err := os.RemoveAll(path); err != nil {
		h.logger.Warn("PAM recording purge: remove failed", zap.String("session_id", sessionID), zap.Error(err))
		return false
	}
	if t := path + ".txt"; isUnderRoot(t, root) {
		if err := os.Remove(t); err != nil && !os.IsNotExist(err) {
			h.logger.Warn("PAM recording purge: transcript remove failed", zap.String("session_id", sessionID), zap.Error(err))
		}
	}
	return true
}

// handleGetPamEntryRecording — GET /pam/sessions/:id/recording (admin).
//
// Streams a PAM entry session's guacd recording, decrypting it on the fly
// when the sealer has sealed it, as handleGetGuacRecording does for route
// sessions. Org-scoped on the session row; 404 when the session has no
// recording, it was purged, or the file is gone; refuses a path outside the
// recordings root. Audited as pam.recording_downloaded.
func (s *Service) handlePamEntryRecording(c *gin.Context) {
	sessionID := c.Param("id")
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var path string
	var sealedAt, purgedAt *time.Time
	err = s.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(recording_path, ''), recording_sealed_at, recording_purged_at
		  FROM pam_entry_sessions WHERE id = $1 AND org_id = $2`, sessionID, org.ID).Scan(&path, &sealedAt, &purgedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
		s.logger.Error("handlePamEntryRecording: lookup failed", logsafe.String("session_id", sessionID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up session"})
		return
	}
	if path == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no recording for this session"})
		return
	}
	if purgedAt != nil {
		c.JSON(http.StatusGone, gin.H{"error": "the recording was removed by the retention policy", "code": "recording_purged"})
		return
	}
	if root := s.config.GuacamoleRecordingPath; root == "" || !isUnderRoot(path, root) {
		s.logger.Warn("handlePamEntryRecording: recording path outside the recordings root", logsafe.String("session_id", sessionID))
		c.JSON(http.StatusNotFound, gin.H{"error": "recording file not found"})
		return
	}
	f, err := os.Open(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "recording file not found on disk"})
		return
	}
	defer f.Close()

	s.logAuditEvent(c, "pam.recording_downloaded", sessionID, "pam_entry_session",
		map[string]interface{}{"session_id": sessionID, "sealed": sealedAt != nil})

	c.Header("Content-Disposition", `attachment; filename="openidx-pam-recording-`+sessionID+`"`)
	c.Header("Content-Type", "application/octet-stream")
	var src io.Reader = f
	if sealedAt != nil {
		if s.guacRecordingRing == nil || !s.guacRecordingRing.Enabled() {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the recording is sealed and no recording key is configured", "code": "recording_key_unavailable"})
			return
		}
		src = newDecryptingReader(f, s.guacRecordingRing, guacRecordingSessionKey(path))
	}
	if _, err := io.Copy(c.Writer, src); err != nil {
		s.logger.Warn("handlePamEntryRecording: copy failed", logsafe.String("session_id", sessionID), zap.Error(err))
	}
}
