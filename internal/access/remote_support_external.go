package access

// A vendor's remote support (Phase 3c): a vendor's technician helps on an
// enrolled device from their own browser, with nothing installed on either
// side beyond the employee's existing agent, when a running engagement covers
// the device. The staff routes (/remote-support/sessions) stay the operator
// tier's; these are the vendor's own, under /my/remote-support/sessions, and
// every one of them answers about the caller's sessions only.
//
// What a vendor's session always is, whatever the request says:
//
//   - covered: the caller is an external user, their account is in effect
//     (externalid.CheckEffective), and a running engagement names them (or
//     names nobody) and lists the device. The janitor ends the session, and
//     evicts both peers, the moment that stops being true: the engagement ends
//     or is closed, the device or the technician leaves it, the account is
//     suspended, or the session reaches expires_at.
//   - bounded: expires_at is the engagement's end or the external session
//     ceiling (externalid.MaxPamSession), whichever is first.
//   - attended: consent_required, so the person at the device Allows it; the
//     agent streams and applies input only after that.
//   - relayed: the relay transport, so the device's video goes through the
//     broker and nowhere else (no peer-to-peer path to the vendor's network).
//   - recorded by the broker: the relay frames are written to the session's
//     recording as IVF (ivfRecorder) by the server, not by the viewer's
//     browser, which belongs to the vendor. A deployment with no recording
//     store refuses the session (externalid.ErrRecordingUnavailable).
//
// The viewer sends input to the device and the device sends only its screen,
// so there is no path for a file or the device's clipboard to leave it other
// than what the recording shows.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// RegisterRemoteSupportVendorRoutes mounts the vendor's own remote-support
// routes. Starting a session asks for a fresh second factor, as the staff
// start does; the rest answer only for sessions the caller started.
func (h *RemoteSupportHandler) RegisterRemoteSupportVendorRoutes(r *gin.RouterGroup, stepUp gin.HandlerFunc) {
	r.GET("/my/remote-support/sessions", h.HandleVendorListSessions)
	r.POST("/my/remote-support/sessions", withGate(stepUp, h.HandleVendorStartSession)...)
	r.POST("/my/remote-support/sessions/:id/end", h.HandleVendorEndSession)
	r.GET("/my/remote-support/sessions/:id/ws", h.HandleVendorWS)
}

type vendorStartRequest struct {
	AgentID string `json:"agent_id" binding:"required"`
	Notes   string `json:"notes"`
}

// vendorSessionPath is where the vendor's viewer connects.
func vendorSessionPath(id string) string {
	return "/api/v1/access/my/remote-support/sessions/" + id + "/ws"
}

// HandleVendorStartSession — POST /my/remote-support/sessions {agent_id}.
func (h *RemoteSupportHandler) HandleVendorStartSession(c *gin.Context) {
	var req vendorStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	org := remoteSupportOrg(c)
	user := getUserID(c)
	if org == "" || user == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}
	refuse := func(status int, err error) {
		h.audit(ctx, "remote_support.vendor_start_denied", req.AgentID, "failure", "user="+user+" code="+externalid.Code(err))
		c.JSON(status, gin.H{"error": err.Error(), "code": externalid.Code(err)})
	}
	st, err := externalid.EngagementFor(ctx, h.db.Pool, org, user, "device", req.AgentID)
	if err != nil {
		h.logger.Error("vendor remote support: engagement check failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check your engagements"})
		return
	}
	if !st.External {
		c.JSON(http.StatusForbidden, gin.H{"error": "this is the vendor support path; staff start sessions from Remote Support", "code": "not_external"})
		return
	}
	if err := externalid.CheckEffective(ctx, h.db.Pool, org, user); err != nil {
		if r := externalid.Refusal(err); r != nil {
			refuse(http.StatusForbidden, r)
			return
		}
		h.logger.Error("vendor remote support: account check failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check your account"})
		return
	}
	if !st.Covered() {
		refuse(http.StatusForbidden, externalid.ErrNoEngagement)
		return
	}
	if h.recordingStore == nil {
		refuse(http.StatusServiceUnavailable, externalid.ErrRecordingUnavailable)
		return
	}
	var enrolled int
	if err := h.db.Pool.QueryRow(ctx, `SELECT 1 FROM enrolled_agents WHERE agent_id = $1 AND org_id = $2`, req.AgentID, org).Scan(&enrolled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
			return
		}
		h.logger.Error("vendor remote support: agent check failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not check the agent"})
		return
	}
	// A session already on the device is someone else's work: the vendor
	// does not supersede it, as a staff start would.
	var busy string
	if err := h.db.Pool.QueryRow(ctx, `
		SELECT id FROM remote_support_sessions
		 WHERE agent_id = $1 AND org_id = $2 AND status IN ('pending', 'active') LIMIT 1`, req.AgentID, org).Scan(&busy); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		h.logger.Error("vendor remote support: busy check failed", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not check for an existing session"})
		return
	}
	if busy != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "the device already has a support session in progress"})
		return
	}
	id := uuid.New().String()
	var expires time.Time
	if err := h.db.Pool.QueryRow(ctx, `
		INSERT INTO remote_support_sessions
		    (id, agent_id, admin_user_id, status, mode, ice_servers, notes, recording_enabled, org_id,
		     consent_required, consent_status, transport, engagement_id, expires_at, server_recording, recording_format)
		VALUES ($1, $2, $3::uuid, 'pending', 'interactive', '[]'::jsonb, $4, false, $5::uuid,
		        true, 'pending', 'relay', $6::uuid, LEAST($7::timestamptz, NOW() + make_interval(secs => $8)), true, 'ivf')
		RETURNING expires_at`,
		id, req.AgentID, user, req.Notes, org, st.EngagementID, st.EndsAt, externalid.MaxPamSession.Seconds()).Scan(&expires); err != nil {
		h.logger.Error("vendor remote support: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start session"})
		return
	}
	h.audit(ctx, "remote_support.vendor_session_started", id, "success",
		"agent="+req.AgentID+" user="+user+" engagement="+st.EngagementID+" recording=server consent=required transport=relay")
	c.JSON(http.StatusCreated, gin.H{
		"id": id, "status": "pending", "agent_id": req.AgentID, "mode": "interactive", "transport": "relay",
		"admin_ws": vendorSessionPath(id), "consent_required": true, "consent_status": "pending",
		"recording": "server", "engagement_id": st.EngagementID, "expires_at": expires,
	})
}

// vendorSession is a vendor's session as its owner sees it.
type vendorSession struct {
	ID            string     `json:"id"`
	AgentID       string     `json:"agent_id"`
	DeviceName    string     `json:"device_name"`
	Status        string     `json:"status"`
	ConsentStatus string     `json:"consent_status"`
	EngagementID  string     `json:"engagement_id"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	EndReason     string     `json:"end_reason,omitempty"`
	WSPath        string     `json:"admin_ws,omitempty"`
}

// HandleVendorListSessions — GET /my/remote-support/sessions: the caller's
// own vendor sessions, newest first.
func (h *RemoteSupportHandler) HandleVendorListSessions(c *gin.Context) {
	ctx := c.Request.Context()
	org, user := remoteSupportOrg(c), getUserID(c)
	if org == "" || user == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	rows, err := h.db.Pool.Query(ctx, `
		SELECT s.id::text, s.agent_id, COALESCE(NULLIF(ag.metadata->>'hostname', ''), s.agent_id), s.status, s.consent_status,
		       COALESCE(s.engagement_id::text, ''), s.started_at, s.ended_at, s.expires_at, COALESCE(s.end_reason, '')
		  FROM remote_support_sessions s
		  LEFT JOIN enrolled_agents ag ON ag.agent_id = s.agent_id AND ag.org_id = s.org_id
		 WHERE s.org_id = $1::uuid AND s.admin_user_id = $2::uuid AND s.engagement_id IS NOT NULL
		 ORDER BY s.started_at DESC LIMIT 100`, org, user)
	if err != nil {
		h.logger.Error("vendor remote support: list failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list your sessions"})
		return
	}
	defer rows.Close()
	out := []vendorSession{}
	for rows.Next() {
		var s vendorSession
		if err := rows.Scan(&s.ID, &s.AgentID, &s.DeviceName, &s.Status, &s.ConsentStatus, &s.EngagementID,
			&s.StartedAt, &s.EndedAt, &s.ExpiresAt, &s.EndReason); err != nil {
			h.logger.Error("vendor remote support: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list your sessions"})
			return
		}
		if s.Status == "pending" || s.Status == "active" {
			s.WSPath = vendorSessionPath(s.ID)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("vendor remote support: list failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list your sessions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": out})
}

// ownVendorSession reports whether session id is a live vendor session the
// caller started and its engagement still allows. It answers 404 itself for
// anything else, so a vendor learns nothing about other sessions.
func (h *RemoteSupportHandler) ownVendorSession(c *gin.Context, id string) bool {
	ctx := c.Request.Context()
	org, user := remoteSupportOrg(c), getUserID(c)
	if org == "" || user == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return false
	}
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return false
	}
	var live bool
	err := h.db.Pool.QueryRow(ctx, `
		SELECT `+vendorSessionAllowed+`
		  FROM remote_support_sessions s
		 WHERE s.id = $1::uuid AND s.org_id = $2::uuid AND s.admin_user_id = $3::uuid AND s.engagement_id IS NOT NULL`,
		id, org, user).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !live) {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return false
	}
	if err != nil {
		h.logger.Error("vendor remote support: session check failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check the session"})
		return false
	}
	return true
}

// vendorSessionAllowed is true when vendor session s may run now: live, not
// past expires_at, and its engagement running and still covering both the
// device and the technician, whose account is in effect.
const vendorSessionAllowed = `(s.status IN ('pending', 'active') AND (s.expires_at IS NULL OR s.expires_at > NOW())
	AND EXISTS (
		SELECT 1 FROM vendor_engagements e
		  JOIN vendor_engagement_targets t ON t.engagement_id = e.id AND t.org_id = e.org_id
		       AND t.target_type = 'device' AND t.target_id = s.agent_id
		  JOIN users u ON u.id = s.admin_user_id AND u.org_id = e.org_id
		 WHERE e.id = s.engagement_id AND e.status = 'open' AND e.starts_at <= NOW() AND e.ends_at > NOW()
		   AND u.user_type = 'external' AND u.vendor_org_id = e.vendor_org_id
		   AND u.account_status = 'active' AND COALESCE(u.enabled, false)
		   AND (cardinality(e.member_user_ids) = 0 OR u.id = ANY (e.member_user_ids))))`

// HandleVendorWS — GET /my/remote-support/sessions/:id/ws: the vendor's
// viewer, on their own live session only.
func (h *RemoteSupportHandler) HandleVendorWS(c *gin.Context) {
	id := c.Param("id")
	if !h.ownVendorSession(c, id) {
		return
	}
	var respHeader http.Header
	if proto := c.GetHeader("Sec-WebSocket-Protocol"); proto != "" {
		if sub := strings.TrimSpace(strings.Split(proto, ",")[0]); sub != "" {
			respHeader = http.Header{"Sec-WebSocket-Protocol": []string{sub}}
		}
	}
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, respHeader)
	if err != nil {
		h.logger.Warn("HandleVendorWS: upgrade failed", zap.Error(err))
		return
	}
	h.runPeer(c.Request.Context(), id, conn, peerAdmin)
}

// HandleVendorEndSession — POST /my/remote-support/sessions/:id/end.
func (h *RemoteSupportHandler) HandleVendorEndSession(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")
	org, user := remoteSupportOrg(c), getUserID(c)
	if org == "" || user == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	tag, err := h.db.Pool.Exec(ctx, `
		UPDATE remote_support_sessions SET status = 'ended', ended_at = NOW(), end_reason = 'ended_by_vendor'
		 WHERE id = $1::uuid AND org_id = $2::uuid AND admin_user_id = $3::uuid AND engagement_id IS NOT NULL
		   AND status IN ('pending', 'active')`, id, org, user)
	if err != nil {
		h.logger.Error("vendor remote support: end failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to end the session"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	h.evictSession(id)
	h.audit(ctx, "remote_support.vendor_session_ended", id, "success", "user="+user)
	c.JSON(http.StatusOK, gin.H{"status": "ended"})
}

// endLapsedVendorSessions ends every vendor session its engagement no longer
// allows and evicts both peers. Run by the janitor on each tick.
func (h *RemoteSupportHandler) endLapsedVendorSessions(ctx context.Context) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	//orgscope:ignore vendor-session sweep — install-wide under the janitor's explicit bypass; each row is ended by primary key
	rows, err := h.db.Pool.Query(orgctx.WithBypassRLS(ctx), `
		UPDATE remote_support_sessions s
		   SET status = 'ended', ended_at = NOW(),
		       end_reason = CASE WHEN s.expires_at IS NOT NULL AND s.expires_at <= NOW() THEN 'session_limit' ELSE 'engagement_ended' END
		 WHERE s.engagement_id IS NOT NULL AND s.status IN ('pending', 'active') AND NOT `+vendorSessionAllowed+`
		RETURNING s.id::text, s.end_reason`)
	if err != nil {
		h.logger.Warn("endLapsedVendorSessions: update failed", zap.Error(err))
		return
	}
	type ended struct{ id, reason string }
	var list []ended
	for rows.Next() {
		var e ended
		if rows.Scan(&e.id, &e.reason) == nil {
			list = append(list, e)
		}
	}
	rows.Close()
	for _, e := range list {
		h.evictSession(e.id)
		h.audit(ctx, "remote_support.vendor_session_ended", e.id, "enforced", "reason="+e.reason)
	}
}

// ---- Broker-side recording (IVF) ----

// ivfRecorder writes the relay frames the device sends to the session's
// recording as an IVF file: a 32-byte file header (written once, at the
// first keyframe, which carries the frame size), then per frame a 12-byte
// header (size, presentation time in milliseconds) and the VP8 frame. Frames
// arrive on the broker's read loop and are handed to a goroutine over a
// buffered channel, so the disk and the database never stall the relay; a
// frame that finds the channel full is dropped and counted. Presentation
// times run from the session's start, so a recorder resumed after a restart
// continues the same timeline (and writes no second file header).
type ivfRecorder struct {
	h         *RemoteSupportHandler
	sessionID string
	orgID     string
	start     time.Time
	frames    chan []byte
	done      chan struct{}
	headed    bool
	chunk     int
	dropped   atomic.Int64
	closeOnce sync.Once
}

const (
	ivfFlushBytes    = 256 << 10
	ivfFlushInterval = 2 * time.Second
	ivfQueue         = 512
)

// recordRelayFrame hands a device frame to the session's recorder, opening
// it on the session's first frame when the session is broker-recorded.
func (h *RemoteSupportHandler) recordRelayFrame(sessionID string, frame []byte) {
	rec := h.recorderFor(sessionID)
	if rec == nil {
		return
	}
	buf := make([]byte, len(frame))
	copy(buf, frame)
	select {
	case rec.frames <- buf:
	default:
		rec.dropped.Add(1)
	}
}

// recorderFor returns the session's recorder, or nil when the session is not
// broker-recorded or no longer live. The answer is cached per session, the
// "no" included, so frames a device still sends after its session ended
// never reopen a recording that was finalized.
func (h *RemoteSupportHandler) recorderFor(sessionID string) *ivfRecorder {
	h.recMu.Lock()
	defer h.recMu.Unlock()
	if rec, seen := h.recorders[sessionID]; seen {
		return rec
	}
	if h.recorders == nil {
		h.recorders = map[string]*ivfRecorder{}
	}
	if h.db == nil || h.db.Pool == nil || h.recordingStore == nil {
		h.recorders[sessionID] = nil
		return nil
	}
	var on bool
	var org string
	var started time.Time
	var size int64
	var chunks int
	//orgscope:ignore the broker records a session it already serves, keyed by primary key; the device side carries no tenant
	err := h.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()), `
		SELECT server_recording, COALESCE(org_id::text, ''), started_at, recording_size_bytes, recording_chunk_count
		  FROM remote_support_sessions WHERE id = $1 AND status IN ('pending', 'active')`, sessionID).Scan(&on, &org, &started, &size, &chunks)
	if err != nil || !on {
		h.recorders[sessionID] = nil
		return nil
	}
	rec := &ivfRecorder{h: h, sessionID: sessionID, orgID: org, start: started, frames: make(chan []byte, ivfQueue),
		done: make(chan struct{}), headed: size > 0, chunk: chunks}
	h.recorders[sessionID] = rec
	go rec.run()
	return rec
}

// closeRecorder flushes and closes the session's recorder, marking the
// recording finalized. Safe to call for a session with none.
func (h *RemoteSupportHandler) closeRecorder(sessionID string) {
	h.recMu.Lock()
	rec := h.recorders[sessionID]
	delete(h.recorders, sessionID)
	h.recMu.Unlock()
	if rec != nil {
		rec.closeOnce.Do(func() { close(rec.frames) })
		<-rec.done
	}
}

func (r *ivfRecorder) run() {
	defer close(r.done)
	var buf bytes.Buffer
	ticker := time.NewTicker(ivfFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case frame, ok := <-r.frames:
			if !ok {
				r.flush(&buf, true)
				return
			}
			r.add(&buf, frame)
			if buf.Len() >= ivfFlushBytes {
				r.flush(&buf, false)
			}
		case <-ticker.C:
			r.flush(&buf, false)
		}
	}
}

// add appends one relay frame (a flags byte, bit 0 = keyframe, then the VP8
// frame) to buf. Until the first keyframe nothing is written: a decoder
// needs one to start, and it carries the frame size the file header holds.
func (r *ivfRecorder) add(buf *bytes.Buffer, frame []byte) {
	if len(frame) < 2 {
		return
	}
	vp8 := frame[1:]
	if !r.headed {
		w, h, ok := vp8KeyframeSize(vp8)
		if !ok {
			return
		}
		buf.Write(ivfFileHeader(w, h))
		r.headed = true
	}
	var fh [12]byte
	binary.LittleEndian.PutUint32(fh[0:4], uint32(len(vp8)))
	binary.LittleEndian.PutUint64(fh[4:12], uint64(time.Since(r.start).Milliseconds()))
	buf.Write(fh[:])
	buf.Write(vp8)
}

func (r *ivfRecorder) flush(buf *bytes.Buffer, final bool) {
	ctx := orgctx.WithBypassRLS(context.Background())
	if buf.Len() > 0 {
		n, err := r.h.recordingStore.Append(r.sessionID, r.chunk, bytes.NewReader(buf.Bytes()))
		buf.Reset()
		if err != nil {
			r.h.logger.Error("vendor session recording: append failed", logsafe.String("session_id", r.sessionID), zap.Error(err))
		} else {
			r.chunk++
			//orgscope:ignore the broker's recorder updates the session it records, by primary key
			if _, err := r.h.db.Pool.Exec(ctx, `
				UPDATE remote_support_sessions
				   SET recording_size_bytes = recording_size_bytes + $2, recording_chunk_count = recording_chunk_count + 1,
				       recording_storage_key = $3, recording_url = $4
				 WHERE id = $1`, r.sessionID, n, r.h.recordingStore.Key(r.sessionID),
				"/api/v1/access/remote-support/sessions/"+r.sessionID+"/recording"); err != nil {
				r.h.logger.Warn("vendor session recording: progress not recorded", logsafe.String("session_id", r.sessionID), zap.Error(err))
			}
		}
	}
	if final {
		//orgscope:ignore the broker's recorder finalizes the session it recorded, by primary key
		if _, err := r.h.db.Pool.Exec(ctx, `
			UPDATE remote_support_sessions SET recording_finalized_at = NOW()
			 WHERE id = $1 AND recording_size_bytes > 0`, r.sessionID); err != nil {
			r.h.logger.Warn("vendor session recording: finalize not recorded", logsafe.String("session_id", r.sessionID), zap.Error(err))
		}
		if d := r.dropped.Load(); d > 0 {
			r.h.logger.Warn("vendor session recording dropped frames under backpressure",
				logsafe.String("session_id", r.sessionID), zap.Int64("dropped", d))
		}
	}
}

// ivfFileHeader is the 32-byte IVF header for VP8 at w x h, timed in
// milliseconds. The frame count is left 0: readers count frames themselves.
func ivfFileHeader(w, h uint16) []byte {
	b := make([]byte, 32)
	copy(b[0:4], "DKIF")
	binary.LittleEndian.PutUint16(b[4:6], 0)
	binary.LittleEndian.PutUint16(b[6:8], 32)
	copy(b[8:12], "VP80")
	binary.LittleEndian.PutUint16(b[12:14], w)
	binary.LittleEndian.PutUint16(b[14:16], h)
	binary.LittleEndian.PutUint32(b[16:20], 1000)
	binary.LittleEndian.PutUint32(b[20:24], 1)
	return b
}

// vp8KeyframeSize reads the frame size from a VP8 keyframe: the 3-byte frame
// tag (bit 0 clear on a keyframe), the start code 9d 01 2a, then 14-bit
// width and height.
func vp8KeyframeSize(f []byte) (w, h uint16, ok bool) {
	if len(f) < 10 || f[0]&0x01 != 0 || f[3] != 0x9d || f[4] != 0x01 || f[5] != 0x2a {
		return 0, 0, false
	}
	w = binary.LittleEndian.Uint16(f[6:8]) & 0x3fff
	h = binary.LittleEndian.Uint16(f[8:10]) & 0x3fff
	return w, h, w > 0 && h > 0
}
