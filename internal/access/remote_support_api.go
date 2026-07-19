// Package access — Phase 4 remote-support session management and WebRTC
// signaling broker. The broker is intentionally in-memory and per-process:
// session state survives in Postgres, but the live signaling channel is
// best-effort. A reconnect on either side re-creates the broker entry by
// re-reading the row.
//
// Wire flow:
//
//  1. Admin POSTs /api/v1/access/remote-support/sessions {agent_id, mode}
//     → row inserted with status='pending', returns session_id.
//  2. /agent/config for that agent_id now embeds a remote_support block
//     pointing at the agent-side WS path (signed with the agent's auth
//     token so only the targeted device can join).
//  3. Agent connects to WS /agent/remote-support/sessions/:id.
//  4. Admin connects to WS /api/v1/access/remote-support/sessions/:id/ws.
//  5. Broker relays SDP offer / answer / ICE candidates. status flips to
//     'active' when both sides are connected.
//  6. Either side POSTs .../end OR closes its WS → status='ended'.
//
// Audit events ride the agent handler's logger so all device lifecycle
// activity sits in one unified_audit_events stream.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	apperrors "github.com/openidx/openidx/internal/common/errors"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// RemoteSupportHandler owns the broker (peer registry + signaling fan-out)
// and the admin HTTP surface. Construct one per access-service instance.
type RemoteSupportHandler struct {
	logger               *zap.Logger
	db                   *database.PostgresDB
	auditAgent           *AgentAPIHandler
	turn                 *TurnMinter
	recordingStore       recordingStore
	defaultRetentionDays int
	// guacRecordingsRoot is the configured GuacamoleRecordingPath (directory).
	// The Guac retention sweeper uses it to guard against accidentally deleting
	// the entire recordings root when recording_path is missing or equals the root.
	guacRecordingsRoot string
	// guacamoleClient is used by the session-end detection sweep to query
	// live active sessions from the Guacamole REST API. Optional — when nil
	// the sweep is skipped (fail-safe: we never mark sessions ended if we
	// cannot see the live set).
	guacamoleClient *GuacamoleClient
	upgrader        websocket.Upgrader

	mu       sync.Mutex
	sessions map[string]*signalingSession
}

// NewRemoteSupportHandler constructs the handler. auditAgent is optional;
// when present, every lifecycle transition lands in unified_audit_events.
func NewRemoteSupportHandler(logger *zap.Logger, db *database.PostgresDB, auditAgent *AgentAPIHandler) *RemoteSupportHandler {
	return &RemoteSupportHandler{
		logger:     logger,
		db:         db,
		auditAgent: auditAgent,
		sessions:   make(map[string]*signalingSession),
		upgrader: websocket.Upgrader{
			ReadBufferSize:   2048,
			WriteBufferSize:  2048,
			HandshakeTimeout: 10 * time.Second,
			// Origin verification is enforced by APISIX upstream; broker
			// itself accepts any origin so localhost dev (admin console
			// proxied through APISIX) works without per-host config.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// SetTurnMinter installs the per-session TURN credential minter. Optional —
// when unset, HandleStartSession falls back to admin-supplied ice_servers
// (or empty if neither is configured).
func (h *RemoteSupportHandler) SetTurnMinter(m *TurnMinter) {
	h.turn = m
}

// SetDefaultRetentionDays installs the bottom-of-chain default that
// applies when neither a session override nor a per-org policy exists.
// Zero means "use the hard fallback (90)".
func (h *RemoteSupportHandler) SetDefaultRetentionDays(days int) {
	h.defaultRetentionDays = days
}

// SetGuacRecordingsRoot stores the configured Guacamole recording directory
// root so the Guac retention sweeper can validate paths before calling
// os.RemoveAll, preventing accidental deletion of the entire recordings root.
func (h *RemoteSupportHandler) SetGuacRecordingsRoot(root string) {
	h.guacRecordingsRoot = root
}

// SetGuacamoleClient wires the Guacamole REST client used by the
// session-end detection sweep. Without this, detectEndedGuacSessions is a
// no-op (fail-safe: sessions are never marked ended when the live set is
// unavailable).
func (h *RemoteSupportHandler) SetGuacamoleClient(gc *GuacamoleClient) {
	h.guacamoleClient = gc
}

// signalingSession is the live broker record for a session that has at
// least one peer connected. mu protects the conn pointers; everything else
// is immutable for the session's lifetime.
type signalingSession struct {
	sessionID string

	mu        sync.Mutex
	adminConn *websocket.Conn
	agentConn *websocket.Conn
}

// RegisterRemoteSupportAdminRoutes mounts the admin (and admin-WS) surface.
// MUST go behind middleware.Auth.
func (h *RemoteSupportHandler) RegisterRemoteSupportAdminRoutes(r *gin.RouterGroup) {
	r.GET("/remote-support/sessions", h.HandleListSessions)
	r.POST("/remote-support/sessions", h.HandleStartSession)
	r.GET("/remote-support/sessions/:id", h.HandleGetSession)
	r.POST("/remote-support/sessions/:id/end", h.HandleEndSession)
	// Admin-side WebSocket — the browser viewer connects here.
	r.GET("/remote-support/sessions/:id/ws", h.HandleAdminWS)
	// Recording upload pipeline (Phase 4 follow-up).
	r.POST("/remote-support/sessions/:id/recording/chunk", h.HandleUploadRecordingChunk)
	r.POST("/remote-support/sessions/:id/recording/finalize", h.HandleFinalizeRecording)
	r.GET("/remote-support/sessions/:id/recording", h.HandleDownloadRecording)
	// Per-tenant retention policy.
	h.RegisterRetentionAdminRoutes(r)
	// Legal hold workflow (exempts a session's recording from sweep).
	h.RegisterLegalHoldAdminRoutes(r)
}

// RegisterRemoteSupportPublicRoutes mounts the agent-facing WebSocket. It
// authenticates via X-Agent-ID + X-Auth-Token headers (same pattern as
// /agent/report) since agents don't have a tenant JWT.
func (h *RemoteSupportHandler) RegisterRemoteSupportPublicRoutes(r *gin.RouterGroup) {
	r.GET("/agent/remote-support/sessions/:id/ws", h.HandleAgentWS)
	// Device consent (attended support): the agent Allows/Denies before the
	// admin can view/control. Agent-authenticated (X-Agent-ID + X-Auth-Token).
	r.POST("/agent/remote-support/sessions/:id/consent", h.HandleAgentConsent)
}

// startSessionRequest is the body accepted by HandleStartSession.
type startSessionRequest struct {
	AgentID    string          `json:"agent_id" binding:"required"`
	Mode       string          `json:"mode"`        // "view" | "interactive" (default)
	ICEServers json.RawMessage `json:"ice_servers"` // optional override
	Notes      string          `json:"notes"`
	Record     bool            `json:"record"` // opt-in MediaRecorder capture
	// ConsentRequired: when true, the person at the device must Allow the
	// session (attended support) before the admin can view/control. Servers /
	// unattended targets leave this false (today's behavior).
	ConsentRequired bool `json:"consent_required"`
	// RecordingRetentionDays: per-session retention override. nil means
	// "use the per-org policy or default". 0 means "infinite". Positive
	// values cap the recording lifetime to that many days.
	RecordingRetentionDays *int `json:"recording_retention_days,omitempty"`
}

// remoteSessionRow is what we return to admins (list + get + start).
type remoteSessionRow struct {
	ID                   string          `json:"id"`
	AgentID              string          `json:"agent_id"`
	AdminUserID          string          `json:"admin_user_id,omitempty"`
	Status               string          `json:"status"`
	Mode                 string          `json:"mode"`
	ICEServers           json.RawMessage `json:"ice_servers"`
	EndReason            string          `json:"end_reason,omitempty"`
	RecordingURL         string          `json:"recording_url,omitempty"`
	RecordingEnabled     bool            `json:"recording_enabled"`
	RecordingSizeBytes   int64           `json:"recording_size_bytes,omitempty"`
	RecordingChunkCount  int             `json:"recording_chunk_count,omitempty"`
	RecordingFinalizedAt *time.Time      `json:"recording_finalized_at,omitempty"`
	StartedAt            time.Time       `json:"started_at"`
	AcceptedAt           *time.Time      `json:"accepted_at,omitempty"`
	EndedAt              *time.Time      `json:"ended_at,omitempty"`
	Notes                string          `json:"notes,omitempty"`
	LastActivityAt       time.Time       `json:"last_activity_at"`
	// IsOnLegalHold derives from a LEFT JOIN against recording_legal_holds
	// — true when at least one row exists with released_at IS NULL for
	// this session. The admin UI uses this to render a lock icon next to
	// the recording link.
	IsOnLegalHold bool `json:"is_on_legal_hold"`
}

// HandleStartSession creates a new session targeting an enrolled agent.
func (h *RemoteSupportHandler) HandleStartSession(c *gin.Context) {
	var req startSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	mode := req.Mode
	if mode == "" {
		mode = "interactive"
	}
	if mode != "interactive" && mode != "view" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'interactive' or 'view'"})
		return
	}
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	// Reject if the agent has another active session already (broker would
	// happily run two, but the UX of two admins sharing a screen is bad).
	var blockingID string
	_ = h.db.Pool.QueryRow(c.Request.Context(), `
        SELECT id FROM remote_support_sessions
         WHERE agent_id = $1 AND status IN ('pending','active')
         LIMIT 1
    `, req.AgentID).Scan(&blockingID)
	if blockingID != "" {
		c.JSON(http.StatusConflict, gin.H{
			"error":      "agent already has an active session",
			"session_id": blockingID,
		})
		return
	}

	adminID := getUserID(c)
	id := uuid.New().String()

	// Resolve ice_servers in priority order:
	//   1. Admin-supplied (verbatim, back-compat).
	//   2. Minted per-session TURN credentials when the minter is wired.
	//   3. Empty array — LAN / Ziti-overlay-only mode.
	ice := req.ICEServers
	mintedTurn := false
	if len(ice) == 0 {
		if h.turn != nil {
			minted, mintErr := h.turn.MintAsRawJSON(id)
			if mintErr != nil {
				h.logger.Warn("HandleStartSession: TURN mint failed; continuing without",
					zap.String("session_id", id), zap.Error(mintErr))
			} else {
				ice = minted
				mintedTurn = true
			}
		}
		if len(ice) == 0 {
			ice = json.RawMessage(`[]`)
		}
	}

	recordingEnabled := req.Record && h.recordingStore != nil
	orgID := getOrgID(c)
	var retentionArg interface{}
	if req.RecordingRetentionDays != nil {
		retentionArg = *req.RecordingRetentionDays
	}
	var orgArg interface{}
	if orgID != "" {
		orgArg = orgID
	}
	_, err := h.db.Pool.Exec(c.Request.Context(), `
        INSERT INTO remote_support_sessions
            (id, agent_id, admin_user_id, status, mode, ice_servers, notes,
             recording_enabled, org_id, recording_retention_days,
             consent_required, consent_status)
        VALUES ($1, $2, NULLIF($3,'')::uuid, 'pending', $4, $5::jsonb, $6,
                $7, $8::uuid, $9, $10, $11)
    `, id, req.AgentID, adminID, mode, string(ice), req.Notes,
		recordingEnabled, orgArg, retentionArg,
		req.ConsentRequired, consentStatusFor(req.ConsentRequired))
	if err != nil {
		h.logger.Error("HandleStartSession: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start session"})
		return
	}

	auditDetail := "agent=" + req.AgentID + " admin=" + adminID
	if mintedTurn {
		auditDetail += " turn=minted"
	}
	if recordingEnabled {
		auditDetail += " recording=on"
	}
	h.audit(c.Request.Context(), "remote_support.session_started", id, "success", auditDetail)

	c.JSON(http.StatusCreated, gin.H{
		"id":                id,
		"status":            "pending",
		"agent_id":          req.AgentID,
		"mode":              mode,
		"admin_ws":          "/api/v1/access/remote-support/sessions/" + id + "/ws",
		"agent_ws":          "/api/v1/access/agent/remote-support/sessions/" + id + "/ws",
		"ice_servers":       ice,
		"recording_enabled": recordingEnabled,
		"consent_required":  req.ConsentRequired,
		"consent_status":    consentStatusFor(req.ConsentRequired),
	})
}

// consentStatusFor returns the initial consent_status for a session: 'pending'
// when the device must Allow first, otherwise 'granted' (unattended/server —
// no behavior change).
func consentStatusFor(required bool) string {
	if required {
		return "pending"
	}
	return "granted"
}

// consentDecisionRequest is the body of the agent accept/decline call.
type consentDecisionRequest struct {
	Decision string `json:"decision"` // "grant" | "deny"
}

// HandleAgentConsent is the DEVICE side of attended-support consent:
// POST /api/v1/access/agent/remote-support/sessions/:id/consent {decision}.
// The agent proves ownership with X-Agent-ID + X-Auth-Token (same as the agent
// WS). It flips consent_status to granted/denied; a denial also ends the
// session so the admin can never view/control without an explicit Allow.
func (h *RemoteSupportHandler) HandleAgentConsent(c *gin.Context) {
	id := c.Param("id")
	row, err := h.fetchSession(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	agentID := c.GetHeader("X-Agent-ID")
	authToken := c.GetHeader("X-Auth-Token")
	if agentID != row.AgentID || authToken == "" || !h.verifyAgentAuth(c.Request.Context(), agentID, authToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "agent credentials invalid"})
		return
	}
	var req consentDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	var newStatus string
	switch req.Decision {
	case "grant":
		newStatus = "granted"
	case "deny":
		newStatus = "denied"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be 'grant' or 'deny'"})
		return
	}

	if newStatus == "denied" {
		// A denial ends the session immediately (fail-closed).
		_, _ = h.db.Pool.Exec(c.Request.Context(), `
            UPDATE remote_support_sessions
               SET consent_status='denied', consent_decided_at=NOW(),
                   status='ended', ended_at=NOW(), end_reason='consent denied by device'
             WHERE id=$1`, id)
		h.audit(c.Request.Context(), "remote_support.consent_denied", id, "success", "agent="+agentID)
		c.JSON(http.StatusOK, gin.H{"consent_status": "denied", "status": "ended"})
		return
	}

	_, _ = h.db.Pool.Exec(c.Request.Context(), `
        UPDATE remote_support_sessions
           SET consent_status='granted', consent_decided_at=NOW()
         WHERE id=$1`, id)
	h.audit(c.Request.Context(), "remote_support.consent_granted", id, "success", "agent="+agentID)
	c.JSON(http.StatusOK, gin.H{"consent_status": "granted"})
}

// HandleListSessions returns recent sessions, newest first.
func (h *RemoteSupportHandler) HandleListSessions(c *gin.Context) {
	if h.db == nil || h.db.Pool == nil {
		c.JSON(http.StatusOK, []remoteSessionRow{})
		return
	}
	rows, err := h.db.Pool.Query(c.Request.Context(), `
        SELECT s.id, s.agent_id, COALESCE(s.admin_user_id::text,''), s.status, s.mode,
               s.ice_servers, COALESCE(s.end_reason,''), COALESCE(s.recording_url,''),
               s.recording_enabled, s.recording_size_bytes, s.recording_chunk_count,
               s.recording_finalized_at,
               s.started_at, s.accepted_at, s.ended_at, COALESCE(s.notes,''),
               s.last_activity_at,
               EXISTS (SELECT 1 FROM recording_legal_holds rlh
                        WHERE rlh.session_id = s.id AND rlh.released_at IS NULL)
          FROM remote_support_sessions s
         ORDER BY s.started_at DESC
         LIMIT 200
    `)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list"})
		return
	}
	defer rows.Close()
	out := []remoteSessionRow{}
	for rows.Next() {
		rec, scanErr := scanRemoteSessionRow(rows)
		if scanErr != nil {
			h.logger.Warn("HandleListSessions: scan", zap.Error(scanErr))
			continue
		}
		out = append(out, rec)
	}
	c.JSON(http.StatusOK, out)
}

// HandleGetSession returns one session.
func (h *RemoteSupportHandler) HandleGetSession(c *gin.Context) {
	id := c.Param("id")
	row, err := h.fetchSession(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("get session", err), h.logger)
		return
	}
	c.JSON(http.StatusOK, row)
}

// HandleEndSession admin-initiated session termination.
func (h *RemoteSupportHandler) HandleEndSession(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Reason == "" {
		body.Reason = "admin_ended"
	}
	if err := h.endSession(c.Request.Context(), id, body.Reason); err != nil {
		apperrors.HandleErrorWithLogger(c, apperrors.Internal("end session", err), h.logger)
		return
	}
	h.audit(c.Request.Context(), "remote_support.session_ended", id, "success", body.Reason)
	c.JSON(http.StatusOK, gin.H{"status": "ended", "id": id})
}

// HandleAdminWS handles the admin (browser) side of signaling.
func (h *RemoteSupportHandler) HandleAdminWS(c *gin.Context) {
	id := c.Param("id")
	if _, err := h.fetchSession(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	// Consent gate (attended support): if the session requires device consent
	// and the device has not yet granted it, the admin must NOT be able to
	// view/control. Refuse the WS until consent is 'granted' (fail-closed). A
	// 'denied' session has already been ended by HandleAgentConsent.
	var consentRequired bool
	var consentStatus string
	if err := h.db.Pool.QueryRow(c.Request.Context(),
		`SELECT consent_required, consent_status FROM remote_support_sessions WHERE id=$1`, id).
		Scan(&consentRequired, &consentStatus); err == nil {
		if consentRequired && consentStatus != "granted" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "awaiting device consent",
				"consent_status": consentStatus,
			})
			return
		}
	}
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Warn("HandleAdminWS: upgrade failed", zap.Error(err))
		return
	}
	h.runPeer(c.Request.Context(), id, conn, peerAdmin)
}

// HandleAgentWS handles the agent (device) side of signaling. The agent
// proves it owns the targeted agent_id by supplying its auth-token in the
// X-Auth-Token header; we verify against enrolled_agents.auth_token_hash.
func (h *RemoteSupportHandler) HandleAgentWS(c *gin.Context) {
	id := c.Param("id")
	row, err := h.fetchSession(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	agentID := c.GetHeader("X-Agent-ID")
	authToken := c.GetHeader("X-Auth-Token")
	if agentID != row.AgentID || authToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "agent credentials invalid"})
		return
	}
	if !h.verifyAgentAuth(c.Request.Context(), agentID, authToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "auth token mismatch"})
		return
	}
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Warn("HandleAgentWS: upgrade failed", zap.Error(err))
		return
	}
	h.runPeer(c.Request.Context(), id, conn, peerAgent)
}

// peerRole identifies which side of the broker a connection represents.
type peerRole int

const (
	peerAdmin peerRole = iota
	peerAgent
)

// runPeer registers the connection in the broker and pumps messages until
// the socket closes. Every received message is relayed verbatim to the
// other peer (if connected) and updates last_activity_at so the janitor
// can age out orphan sessions.
func (h *RemoteSupportHandler) runPeer(ctx context.Context, sessionID string, conn *websocket.Conn, role peerRole) {
	defer conn.Close()

	sess := h.bindPeer(sessionID, conn, role)
	defer h.unbindPeer(sess, role)

	// If both peers are now connected, flip status → active.
	if sess.hasBothPeers() {
		h.markActive(ctx, sessionID)
	}

	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.TextMessage && mt != websocket.BinaryMessage {
			continue
		}
		h.touchSession(ctx, sessionID)
		if target := sess.otherPeer(role); target != nil {
			if writeErr := target.WriteMessage(mt, data); writeErr != nil {
				h.logger.Warn("relay write failed", zap.String("session", sessionID), zap.Error(writeErr))
				return
			}
		}
	}
}

// bindPeer attaches conn to the session broker entry, creating it on first
// peer.
func (h *RemoteSupportHandler) bindPeer(sessionID string, conn *websocket.Conn, role peerRole) *signalingSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok {
		sess = &signalingSession{sessionID: sessionID}
		h.sessions[sessionID] = sess
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	switch role {
	case peerAdmin:
		// If a previous admin connection lingers, drop it.
		if sess.adminConn != nil {
			_ = sess.adminConn.Close()
		}
		sess.adminConn = conn
	case peerAgent:
		if sess.agentConn != nil {
			_ = sess.agentConn.Close()
		}
		sess.agentConn = conn
	}
	return sess
}

// unbindPeer detaches the connection. When neither peer remains we drop the
// broker entry; the session row stays in Postgres until explicitly ended so
// reconnect-after-network-blip works.
func (h *RemoteSupportHandler) unbindPeer(sess *signalingSession, role peerRole) {
	sess.mu.Lock()
	switch role {
	case peerAdmin:
		sess.adminConn = nil
	case peerAgent:
		sess.agentConn = nil
	}
	empty := sess.adminConn == nil && sess.agentConn == nil
	sess.mu.Unlock()
	if !empty {
		return
	}
	h.mu.Lock()
	delete(h.sessions, sess.sessionID)
	h.mu.Unlock()
}

func (s *signalingSession) hasBothPeers() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adminConn != nil && s.agentConn != nil
}

func (s *signalingSession) otherPeer(role peerRole) *websocket.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if role == peerAdmin {
		return s.agentConn
	}
	return s.adminConn
}

// markActive flips a pending session to active when both peers connect.
func (h *RemoteSupportHandler) markActive(ctx context.Context, sessionID string) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	_, _ = h.db.Pool.Exec(ctx, `
        UPDATE remote_support_sessions
           SET status = 'active', accepted_at = COALESCE(accepted_at, NOW()),
               last_activity_at = NOW()
         WHERE id = $1 AND status = 'pending'
    `, sessionID)
	h.audit(ctx, "remote_support.session_active", sessionID, "success", "")
}

// touchSession bumps last_activity_at so a stalled session can be aged out.
func (h *RemoteSupportHandler) touchSession(ctx context.Context, sessionID string) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	_, _ = h.db.Pool.Exec(ctx,
		`UPDATE remote_support_sessions SET last_activity_at = NOW() WHERE id = $1`,
		sessionID)
}

// endSession persists end state and tears down any live broker entry.
func (h *RemoteSupportHandler) endSession(ctx context.Context, sessionID, reason string) error {
	if h.db != nil && h.db.Pool != nil {
		_, err := h.db.Pool.Exec(ctx, `
            UPDATE remote_support_sessions
               SET status = 'ended', ended_at = COALESCE(ended_at, NOW()),
                   end_reason = COALESCE(NULLIF($2,''), end_reason),
                   last_activity_at = NOW()
             WHERE id = $1 AND status IN ('pending','active')
        `, sessionID, reason)
		if err != nil {
			return err
		}
	}
	// Drop any live broker entry so both peers receive a clean close.
	h.mu.Lock()
	sess, ok := h.sessions[sessionID]
	if ok {
		delete(h.sessions, sessionID)
	}
	h.mu.Unlock()
	if sess != nil {
		sess.mu.Lock()
		if sess.adminConn != nil {
			_ = sess.adminConn.Close()
			sess.adminConn = nil
		}
		if sess.agentConn != nil {
			_ = sess.agentConn.Close()
			sess.agentConn = nil
		}
		sess.mu.Unlock()
	}
	return nil
}

// verifyAgentAuth checks the supplied auth token against the
// enrolled_agents.auth_token_hash for the given agent_id.
func (h *RemoteSupportHandler) verifyAgentAuth(ctx context.Context, agentID, token string) bool {
	if h.db == nil || h.db.Pool == nil {
		return token != "" // dev mode: any non-empty token
	}
	var stored string
	err := h.db.Pool.QueryRow(ctx,
		`SELECT auth_token_hash FROM enrolled_agents WHERE agent_id = $1`,
		agentID).Scan(&stored)
	if err != nil {
		return false
	}
	return sha256Hex(token) == stored
}

// activeSessionInfo carries the per-agent session pointer that
// findActiveSessionForAgent returns. Promoted to a struct because the
// recording flag is a fifth datum and the positional-return signature
// was already noisy.
type activeSessionInfo struct {
	SessionID  string
	Mode       string
	ICEServers json.RawMessage
	Recording  bool
}

// findActiveSessionForAgent — called from HandleConfig to embed an in-flight
// session in the agent's config response. Returns the session info when one
// is active or pending for this agent, or `ok=false` when the agent has
// no live session.
func findActiveSessionForAgent(ctx context.Context, db *database.PostgresDB, agentID string) (info activeSessionInfo, ok bool) {
	if db == nil || db.Pool == nil || agentID == "" {
		return activeSessionInfo{}, false
	}
	var iceBytes []byte
	err := db.Pool.QueryRow(ctx, `
        SELECT id, mode, ice_servers, recording_enabled
          FROM remote_support_sessions
         WHERE agent_id = $1 AND status IN ('pending','active')
         ORDER BY started_at DESC
         LIMIT 1
    `, agentID).Scan(&info.SessionID, &info.Mode, &iceBytes, &info.Recording)
	if err != nil {
		return activeSessionInfo{}, false
	}
	info.ICEServers = json.RawMessage(iceBytes)
	return info, true
}

// fetchSession reads the full row by ID for admin handlers.
func (h *RemoteSupportHandler) fetchSession(ctx context.Context, id string) (remoteSessionRow, error) {
	if h.db == nil || h.db.Pool == nil {
		return remoteSessionRow{}, errors.New("database unavailable")
	}
	row := h.db.Pool.QueryRow(ctx, `
        SELECT s.id, s.agent_id, COALESCE(s.admin_user_id::text,''), s.status, s.mode,
               s.ice_servers, COALESCE(s.end_reason,''), COALESCE(s.recording_url,''),
               s.recording_enabled, s.recording_size_bytes, s.recording_chunk_count,
               s.recording_finalized_at,
               s.started_at, s.accepted_at, s.ended_at, COALESCE(s.notes,''),
               s.last_activity_at,
               EXISTS (SELECT 1 FROM recording_legal_holds rlh
                        WHERE rlh.session_id = s.id AND rlh.released_at IS NULL)
          FROM remote_support_sessions s
         WHERE s.id = $1
    `, id)
	return scanRemoteSessionRow(row)
}

func scanRemoteSessionRow(r rowScanner) (remoteSessionRow, error) {
	var rec remoteSessionRow
	var iceBytes []byte
	err := r.Scan(
		&rec.ID, &rec.AgentID, &rec.AdminUserID, &rec.Status, &rec.Mode,
		&iceBytes, &rec.EndReason, &rec.RecordingURL,
		&rec.RecordingEnabled, &rec.RecordingSizeBytes, &rec.RecordingChunkCount,
		&rec.RecordingFinalizedAt,
		&rec.StartedAt, &rec.AcceptedAt, &rec.EndedAt, &rec.Notes,
		&rec.LastActivityAt,
		&rec.IsOnLegalHold,
	)
	rec.ICEServers = json.RawMessage(iceBytes)
	return rec, err
}

func (h *RemoteSupportHandler) audit(ctx context.Context, action, sessionID, outcome, detail string) {
	if h.auditAgent != nil {
		h.auditAgent.logAuditEvent(action, sessionID, outcome, detail)
		h.auditAgent.logAuditEventToDB(ctx, action, sessionID, outcome, detail)
	}
}

// StartJanitor runs a background goroutine that ages out pending/active
// sessions with no signaling activity in `idleAfter`. Janitor restart is
// safe — it operates only on Postgres state, not broker memory.
func (h *RemoteSupportHandler) StartJanitor(ctx context.Context, idleAfter time.Duration, tick time.Duration) {
	ctx = orgctx.WithBypassRLS(ctx)
	go func() {
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.expireOrphanSessions(ctx, idleAfter)
			}
		}
	}()
}

func (h *RemoteSupportHandler) expireOrphanSessions(ctx context.Context, idleAfter time.Duration) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	tag, err := h.db.Pool.Exec(ctx, `
        UPDATE remote_support_sessions
           SET status = 'expired', ended_at = NOW(),
               end_reason = COALESCE(end_reason, 'orphan_timeout')
         WHERE status IN ('pending','active')
           AND last_activity_at < NOW() - $1::interval
    `, idleAfter.String())
	if err != nil {
		h.logger.Warn("expireOrphanSessions: update failed", zap.Error(err))
		return
	}
	if tag.RowsAffected() > 0 {
		h.audit(ctx, "remote_support.session_expired", "(batch)", "enforced",
			"count="+strconv.FormatInt(tag.RowsAffected(), 10))
	}
}
