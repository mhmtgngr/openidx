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
//
// Watching asks for a fresh second factor, as watching a PAM session does
// (pam.sponsor_watch). The viewer is a WebSocket, and the freshness gate
// answers a refusal the console can act on only on an ordinary request, so the
// step-up sits on a POST that mints a watch ticket -- one use, sixty seconds,
// bound to the session and the sponsor -- and the socket opens only with one.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/notifications"
)

// RegisterRemoteSupportSponsorRoutes mounts the sponsor's routes. Minting a
// watch ticket and ending a session each ask for a fresh second factor, under
// actions of their own so the audit tells them apart; listing only looks, and
// the watch socket takes the ticket in place of a gate of its own.
func (h *RemoteSupportHandler) RegisterRemoteSupportSponsorRoutes(r *gin.RouterGroup, watchStepUp, endStepUp gin.HandlerFunc) {
	r.GET("/remote-support/sponsored/sessions", h.HandleSponsorListSessions)
	r.POST("/remote-support/sponsored/sessions/:id/watch-ticket", withGate(watchStepUp, h.HandleSponsorWatchTicket)...)
	r.GET("/remote-support/sponsored/sessions/:id/watch", h.HandleSponsorWatchWS)
	r.POST("/remote-support/sponsored/sessions/:id/end", withGate(endStepUp, h.HandleSponsorEndSession)...)
}

// ---- Watch tickets ----

// watchTicketTTL is how long a minted ticket opens the socket: long enough for
// the browser to connect, short enough that one found later is worthless.
const watchTicketTTL = 60 * time.Second

type watchTicket struct {
	sessionID, userID, orgID string
	expires                  time.Time
}

// watchTicketStore holds the outstanding watch tickets in this process. That
// is enough because the broker is single-replica already: a session's peers
// meet in RemoteSupportHandler.sessions, which is in-process too, so a
// deployment that spread a sponsor's two requests over replicas would have no
// session to watch on the second one either. A restart forgets the tickets,
// which costs the sponsor one more step-up. The zero value is ready.
type watchTicketStore struct {
	mu      sync.Mutex
	tickets map[string]watchTicket
}

// mint issues a ticket for (session, user, org), pruning expired ones.
func (s *watchTicketStore) mint(sessionID, userID, orgID string, now time.Time) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tickets == nil {
		s.tickets = map[string]watchTicket{}
	}
	for k, t := range s.tickets {
		if !now.Before(t.expires) {
			delete(s.tickets, k)
		}
	}
	s.tickets[tok] = watchTicket{sessionID: sessionID, userID: userID, orgID: orgID, expires: now.Add(watchTicketTTL)}
	return tok, nil
}

// consume spends a ticket. It is gone after the first attempt whatever the
// answer, so a ticket presented for the wrong session or by the wrong user
// cannot then be retried for the right one.
func (s *watchTicketStore) consume(tok, sessionID, userID, orgID string, now time.Time) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	t, ok := s.tickets[tok]
	delete(s.tickets, tok)
	s.mu.Unlock()
	return ok && now.Before(t.expires) && t.sessionID == sessionID && t.userID == userID && t.orgID == orgID
}

// HandleSponsorWatchTicket — POST /remote-support/sponsored/sessions/:id/watch-ticket:
// a one-use ticket that opens the sponsor's viewer on a live vendor session
// they sponsor, with the socket path that carries it.
func (h *RemoteSupportHandler) HandleSponsorWatchTicket(c *gin.Context) {
	id := c.Param("id")
	if !h.sponsoredSupportSessionLive(c, id) {
		return
	}
	user := getUserID(c)
	tok, err := h.watchTickets.mint(id, user, remoteSupportOrg(c), time.Now())
	if err != nil {
		h.logger.Error("sponsored remote support: minting a watch ticket failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not prepare the watch"})
		return
	}
	h.audit(c.Request.Context(), "remote_support.sponsor_watch_ticket", id, "success", "user="+user)
	c.JSON(http.StatusOK, gin.H{
		"ticket":     tok,
		"expires_in": int(watchTicketTTL.Seconds()),
		"watch_ws":   sponsorSessionPath(id) + "?ticket=" + tok,
	})
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

// HandleSponsorWatchWS — GET /remote-support/sponsored/sessions/:id/watch?ticket=:
// the sponsor's read-only viewer. It opens only with a ticket from
// watch-ticket minted for this session and this caller, and spends it.
func (h *RemoteSupportHandler) HandleSponsorWatchWS(c *gin.Context) {
	id := c.Param("id")
	if !h.sponsoredSupportSessionLive(c, id) {
		return
	}
	if !h.watchTickets.consume(c.Query("ticket"), id, getUserID(c), remoteSupportOrg(c), time.Now()) {
		h.audit(c.Request.Context(), "remote_support.sponsor_watch", id, "failure", "user="+getUserID(c)+" reason=no_valid_ticket")
		c.JSON(http.StatusForbidden, gin.H{
			"error": "watching needs a watch ticket from POST .../watch-ticket, which asks for a fresh second factor",
			"code":  "watch_ticket_required",
		})
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

// sponsoredSupportLink is where a sponsor's notification sends them: Access
// requests, where the Vendor support sessions panel lists the session with
// Watch and End.
const sponsoredSupportLink = "/access-requests"

// notifySponsorsOfSupportSession tells the sponsors of a vendor session -- the
// technician's sponsor and the engagement's, once each -- that it went live,
// the remote-support counterpart of notifySponsorOfSession for a PAM session.
// Each sponsor told is audited as remote_support.sponsor_notified, and one
// whose write failed as a failure of it; a sponsor who switched the
// notification type off is not told and leaves no record, as on the PAM side.
// Best-effort: the session is already being relayed, and nothing here can end
// it. A staff session, which has no engagement, finds no row and tells no one.
func (h *RemoteSupportHandler) notifySponsorsOfSupportSession(ctx context.Context, orgID, sessionID string) {
	if h.db == nil || h.db.Pool == nil {
		return
	}
	var tech, techID, device, engagementID, engagement, techSponsor, engSponsor string
	err := h.db.Pool.QueryRow(ctx, `
		SELECT COALESCE(NULLIF(u.email, ''), u.username), u.id::text,
		       COALESCE(NULLIF(ag.metadata->>'hostname', ''), s.agent_id), e.id::text, e.title,
		       COALESCE(u.sponsor_user_id::text, ''), COALESCE(e.sponsor_user_id::text, '')
		  FROM remote_support_sessions s
		  JOIN users u ON u.id = s.admin_user_id AND u.org_id = s.org_id
		  JOIN vendor_engagements e ON e.id = s.engagement_id AND e.org_id = s.org_id
		  LEFT JOIN enrolled_agents ag ON ag.agent_id = s.agent_id AND ag.org_id = s.org_id
		 WHERE s.id = $1::uuid AND s.org_id = $2::uuid`, sessionID, orgID).
		Scan(&tech, &techID, &device, &engagementID, &engagement, &techSponsor, &engSponsor)
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if err != nil {
		h.logger.Warn("notify sponsors of a support session: could not read the session", logsafe.String("session_id", sessionID), zap.Error(err))
		return
	}
	notif := notifications.NewService(h.db, h.logger)
	told := map[string]bool{}
	for _, sponsor := range []string{techSponsor, engSponsor} {
		if sponsor == "" || sponsor == techID || told[sponsor] {
			continue
		}
		told[sponsor] = true
		if !notif.Enabled(ctx, sponsor, "in_app", notifications.TypeSponsoredAccess) {
			continue
		}
		if err := notif.CreateMultiChannelNotification(ctx, sponsor, orgID, notifications.TypeSponsoredAccess,
			"A vendor user you sponsor started a remote-support session",
			fmt.Sprintf("%s is connected to %s for %s. The session is recorded; you can watch it or end it.", tech, device, engagement),
			sponsoredSupportLink,
			map[string]interface{}{"session_id": sessionID, "engagement_id": engagementID, "user_id": techID, "kind": "remote_support_session_started"}); err != nil {
			h.logger.Warn("notify sponsors of a support session failed", logsafe.String("session_id", sessionID), zap.String("sponsor_id", sponsor), zap.Error(err))
			h.audit(ctx, "remote_support.sponsor_notified", sessionID, "failure", "sponsor="+sponsor)
			continue
		}
		h.audit(ctx, "remote_support.sponsor_notified", sessionID, "success", "sponsor="+sponsor)
	}
}
