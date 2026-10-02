package access

// The sponsor's view of their external users' live privileged sessions:
// invariant I6 and section 6.10 of the third-party access framework. The
// sponsor, who vouches for a vendor user and approves their launches, sees the
// sessions those launches opened, can watch one read-only, and can end one on
// the broker. None of it needs the administrator role, and each route answers
// only for the external users the caller sponsors.
//
// An external user's session always runs on its own broker connection under
// the user's own broker account (I5), so the sponsor's share key is minted as
// that account, on that connection, on the broker that serves it, and ending
// it ends nobody else's session.

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// SponsoredSession is a live PAM entry session of an external user, as their
// sponsor sees it.
type SponsoredSession struct {
	ID                string     `json:"id"`
	EntryID           string     `json:"entry_id"`
	EntryName         string     `json:"entry_name"`
	UserID            string     `json:"user_id"`
	User              string     `json:"user"`
	StartedAt         time.Time  `json:"started_at"`
	Recorded          bool       `json:"recorded"`
	SponsorNotifiedAt *time.Time `json:"sponsor_notified_at,omitempty"`
}

// handlePamListSponsoredSessions — GET /pam/sponsored/sessions: the live PAM
// entry sessions of the external users the caller sponsors. Empty for anyone
// who sponsors no one.
func (s *Service) handlePamListSponsoredSessions(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT s.id::text, s.entry_id::text, e.name, s.user_id::text, COALESCE(NULLIF(u.email, ''), u.username),
		       s.started_at, COALESCE(s.recording_path, '') <> '', s.sponsor_notified_at
		  FROM pam_entry_sessions s
		  JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		  JOIN users u ON u.id = s.user_id AND u.org_id = s.org_id
		 WHERE s.org_id = $1 AND s.status = 'active'
		   AND u.user_type = 'external' AND u.sponsor_user_id = NULLIF($2,'')::uuid
		 ORDER BY s.started_at DESC`, org.ID, c.GetString("user_id"))
	if err != nil {
		s.logger.Error("handlePamListSponsoredSessions: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	defer rows.Close()
	sessions := []SponsoredSession{}
	for rows.Next() {
		var ss SponsoredSession
		if err := rows.Scan(&ss.ID, &ss.EntryID, &ss.EntryName, &ss.UserID, &ss.User,
			&ss.StartedAt, &ss.Recorded, &ss.SponsorNotifiedAt); err != nil {
			s.logger.Error("handlePamListSponsoredSessions: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
			return
		}
		sessions = append(sessions, ss)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("handlePamListSponsoredSessions: rows failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sessions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// sponsoredSession loads the live session named in the path when its user is
// an external user the caller sponsors, with what the broker needs to find it.
// Anything else -- another sponsor's user, an internal user's session, an
// ended one -- is not found. Reports false once it has answered.
func (s *Service) sponsoredSession(c *gin.Context, orgID string) (pamSessionRow, string, string, bool) {
	var row pamSessionRow
	var entryID, userID string
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		SELECT s.id::text, COALESCE(s.guac_connection_id, ''), COALESCE(s.guac_username, ''), COALESCE(e.reach_mode, ''),
		       s.entry_id::text, s.user_id::text
		  FROM pam_entry_sessions s
		  JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		  JOIN users u ON u.id = s.user_id AND u.org_id = s.org_id
		 WHERE s.id::text = $1 AND s.org_id = $2 AND s.status = 'active'
		   AND u.user_type = 'external' AND u.sponsor_user_id = NULLIF($3,'')::uuid`,
		c.Param("id"), orgID, c.GetString("user_id")).Scan(&row.rowID, &row.connID, &row.guacUser, &row.reach, &entryID, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return row, "", "", false
	}
	if err != nil {
		s.logger.Error("sponsoredSession: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load the session"})
		return row, "", "", false
	}
	return row, entryID, userID, true
}

// handlePamSponsorWatchSession — POST /pam/sponsored/sessions/:id/watch: a
// read-only share URL for the live session, minted as the session's own broker
// account on the broker that serves it, and audited as pam.session_watched.
func (s *Service) handlePamSponsorWatchSession(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	row, entryID, userID, ok := s.sponsoredSession(c, org.ID)
	if !ok {
		return
	}
	broker := s.brokerFor(row.reach)
	if broker == nil || !broker.perUserIdentities || row.connID == "" || row.guacUser == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "this session cannot be watched: its broker does not run it under the user's own broker account",
			"code":  "watch_unavailable",
		})
		return
	}
	active, err := broker.ListActiveSessions(ctx)
	if err != nil {
		s.logger.Warn("watch: listing the broker's sessions failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "the session broker could not be reached", "code": "broker_unreachable"})
		return
	}
	activeID := ""
	for _, a := range active {
		if a.ConnectionIdentifier == row.connID && a.Username == row.guacUser {
			activeID = a.Identifier
			break
		}
	}
	if activeID == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "the broker is not serving this session", "code": "session_not_live"})
		return
	}
	var encPw string
	if err := s.db.Pool.QueryRow(ctx,
		`SELECT guac_password_enc FROM guacamole_users WHERE broker = $1 AND guac_username = $2 AND org_id = $3 LIMIT 1`,
		broker.component, row.guacUser, org.ID).Scan(&encPw); err != nil {
		s.logger.Warn("watch: the session's broker account is not on record", zap.Error(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "this session cannot be watched", "code": "watch_unavailable"})
		return
	}
	pw, err := broker.tokenCipher.Decrypt(encPw)
	if err != nil {
		s.logger.Error("watch: the session's broker account could not be read", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare the watch"})
		return
	}
	shareURL, err := broker.ShareActiveConnectionForOwner(ctx, activeID, row.guacUser, pw)
	if errors.Is(err, ErrSharingUnsupported) {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "the session broker does not support watching a session", "code": "watch_unsupported"})
		return
	}
	if err != nil {
		s.logger.Warn("watch: minting the share failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "the session broker could not share the session", "code": "broker_unreachable"})
		return
	}
	s.logAuditEvent(c, "pam.session_watched", row.rowID, "pam_entry_session", map[string]interface{}{
		"session_id": row.rowID, "entry_id": entryID, "user_id": userID, "read_only": true, "as": "sponsor",
	})
	c.JSON(http.StatusOK, gin.H{"share_url": shareURL, "read_only": true})
}

// handlePamSponsorEndSession — POST /pam/sponsored/sessions/:id/end: ends the
// live session on its broker the kill switch's way (a row is marked ended only
// once the broker no longer serves it), and audits pam.session_ended with
// reason sponsor_ended.
func (s *Service) handlePamSponsorEndSession(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	row, entryID, userID, ok := s.sponsoredSession(c, org.ID)
	if !ok {
		return
	}
	warn := func(step string, err error) {
		s.logger.Warn("sponsor end: the session was not ended",
			zap.String("step", step), zap.String("session_id", logsafe.Clean(row.rowID)), zap.Error(err))
	}
	if ended := s.endPamEntrySessionRows(ctx, org.ID, []pamSessionRow{row}, warn); len(ended) == 0 {
		c.JSON(http.StatusBadGateway, gin.H{"error": "the session broker still serves the session; try again", "code": "session_not_ended"})
		return
	}
	s.logAuditEvent(c, "pam.session_ended", row.rowID, "pam_entry_session", map[string]interface{}{
		"session_id": row.rowID, "entry_id": entryID, "user_id": userID, "reason": sessionEndSponsor,
	})
	s.pamSessionEnded(org.ID, row.rowID, sessionEndSponsor, c.GetString("user_id"))
	c.JSON(http.StatusOK, gin.H{"session_id": row.rowID, "ended": true})
}
