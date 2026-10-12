package access

// A sponsor's view of their vendor's remote support (Phase 3e). The sponsor of
// a vendor technician -- the technician's own sponsor, or the sponsor of the
// engagement the session runs under -- sees the technician's live sessions,
// can watch one, and can end it. Watching is read-only in the broker, not in
// the viewer: a watcher receives the device's relay frames and the broker
// drops everything it sends but a keyframe request (runPeer, peerWatcher), so
// a sponsor's browser cannot drive the device whatever it runs.
//
// Anything that is not a live vendor session the caller sponsors answers 404,
// so a sponsor learns nothing about other sessions.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// RegisterRemoteSupportSponsorRoutes mounts the sponsor's routes. Ending a
// session asks for a fresh second factor; listing and watching only look.
func (h *RemoteSupportHandler) RegisterRemoteSupportSponsorRoutes(r *gin.RouterGroup, stepUp gin.HandlerFunc) {
	r.GET("/remote-support/sponsored/sessions", h.HandleSponsorListSessions)
	r.GET("/remote-support/sponsored/sessions/:id/watch", h.HandleSponsorWatchWS)
	r.POST("/remote-support/sponsored/sessions/:id/end", withGate(stepUp, h.HandleSponsorEndSession)...)
}

// sponsoredBy is true when the vendor session s (its technician u, its
// engagement e) is sponsored by $sponsor: the technician's sponsor or the
// engagement's.
const sponsoredBy = `(u.sponsor_user_id = $2::uuid OR e.sponsor_user_id = $2::uuid)`

// sponsorSessionPath is where the sponsor's read-only viewer connects.
func sponsorSessionPath(id string) string {
	return "/api/v1/access/remote-support/sponsored/sessions/" + id + "/watch"
}

// sponsoredSupportSession is a vendor session as its sponsor sees it.
type sponsoredSupportSession struct {
	ID              string     `json:"id"`
	AgentID         string     `json:"agent_id"`
	DeviceName      string     `json:"device_name"`
	Technician      string     `json:"technician"`
	EngagementID    string     `json:"engagement_id"`
	EngagementTitle string     `json:"engagement_title"`
	Status          string     `json:"status"`
	ConsentStatus   string     `json:"consent_status"`
	StartedAt       time.Time  `json:"started_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	WatchPath       string     `json:"watch_ws"`
}

// HandleSponsorListSessions — GET /remote-support/sponsored/sessions: the
// live vendor sessions the caller sponsors, newest first. Empty for anyone who
// sponsors no one.
func (h *RemoteSupportHandler) HandleSponsorListSessions(c *gin.Context) {
	ctx := c.Request.Context()
	org, user := remoteSupportOrg(c), getUserID(c)
	if org == "" || user == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	rows, err := h.db.Pool.Query(ctx, `
		SELECT s.id::text, s.agent_id, COALESCE(NULLIF(ag.metadata->>'hostname', ''), s.agent_id),
		       COALESCE(NULLIF(u.email, ''), u.username), e.id::text, e.title, s.status, s.consent_status,
		       s.started_at, s.expires_at
		  FROM remote_support_sessions s
		  JOIN users u ON u.id = s.admin_user_id AND u.org_id = s.org_id
		  JOIN vendor_engagements e ON e.id = s.engagement_id AND e.org_id = s.org_id
		  LEFT JOIN enrolled_agents ag ON ag.agent_id = s.agent_id AND ag.org_id = s.org_id
		 WHERE s.org_id = $1::uuid AND s.status IN ('pending', 'active') AND `+sponsoredBy+`
		 ORDER BY s.started_at DESC`, org, user)
	if err != nil {
		h.logger.Error("sponsored remote support: list failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()
	out := []sponsoredSupportSession{}
	for rows.Next() {
		var s sponsoredSupportSession
		if err := rows.Scan(&s.ID, &s.AgentID, &s.DeviceName, &s.Technician, &s.EngagementID, &s.EngagementTitle,
			&s.Status, &s.ConsentStatus, &s.StartedAt, &s.ExpiresAt); err != nil {
			h.logger.Error("sponsored remote support: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
			return
		}
		s.WatchPath = sponsorSessionPath(s.ID)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("sponsored remote support: list failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": out})
}

// sponsoredSupportSessionLive reports whether id is a live vendor session the
// caller sponsors, answering 404 (or the error) itself when it is not.
func (h *RemoteSupportHandler) sponsoredSupportSessionLive(c *gin.Context, id string) bool {
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
	var one int
	err := h.db.Pool.QueryRow(ctx, `
		SELECT 1
		  FROM remote_support_sessions s
		  JOIN users u ON u.id = s.admin_user_id AND u.org_id = s.org_id
		  JOIN vendor_engagements e ON e.id = s.engagement_id AND e.org_id = s.org_id
		 WHERE s.id = $3::uuid AND s.org_id = $1::uuid AND s.status IN ('pending', 'active') AND `+sponsoredBy,
		org, user, id).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return false
	}
	if err != nil {
		h.logger.Error("sponsored remote support: session check failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check the session"})
		return false
	}
	return true
}

// HandleSponsorWatchWS — GET /remote-support/sponsored/sessions/:id/watch:
// the sponsor's read-only viewer.
func (h *RemoteSupportHandler) HandleSponsorWatchWS(c *gin.Context) {
	id := c.Param("id")
	if !h.sponsoredSupportSessionLive(c, id) {
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
		h.logger.Warn("HandleSponsorWatchWS: upgrade failed", zap.Error(err))
		return
	}
	h.audit(c.Request.Context(), "remote_support.sponsor_watch", id, "success", "user="+getUserID(c))
	h.runPeer(c.Request.Context(), id, conn, peerWatcher)
}

// HandleSponsorEndSession — POST /remote-support/sponsored/sessions/:id/end.
func (h *RemoteSupportHandler) HandleSponsorEndSession(c *gin.Context) {
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
		UPDATE remote_support_sessions s SET status = 'ended', ended_at = NOW(), end_reason = 'ended_by_sponsor'
		  FROM users u, vendor_engagements e
		 WHERE s.id = $3::uuid AND s.org_id = $1::uuid AND s.status IN ('pending', 'active')
		   AND u.id = s.admin_user_id AND u.org_id = s.org_id
		   AND e.id = s.engagement_id AND e.org_id = s.org_id AND `+sponsoredBy, org, user, id)
	if err != nil {
		h.logger.Error("sponsored remote support: end failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to end the session"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	h.evictSession(id)
	h.audit(ctx, "remote_support.sponsor_session_ended", id, "success", "user="+user)
	c.JSON(http.StatusOK, gin.H{"status": "ended"})
}
