package access

// Moderation for PAM entries: section 6.10 of the third-party access
// framework, extending the moderation gate of route-based Guacamole
// connections (moderated_sessions.go, PAM C3) to every PAM entry.
//
// An entry that requires a moderator (pam_entries.require_moderator) opens a
// session only while a moderator is watching for it. The user asks for one
// (POST /pam/moderation/request with entry_id). An administrator, or, for an
// external (vendor) user, their sponsor, joins. The user then connects within
// the moderation wait window. The launch claims the moderation in the statement
// that finds it, so one moderation admits one session, and the session row
// names it (pam_entry_sessions.moderation_id). Its moderator watches that
// session read-only and ends it. Once the moderation has ended, the lifecycle
// sweep ends a session the moderator's end could not reach.
//
// Every launch path is held to it:
//   - connect and the route-based connect, through connectPamEntry;
//   - the Windows app launch;
//   - the browser SSH terminal and an SSH certificate, which run no session a
//     moderator could watch, and so refuse a moderated entry outright;
//   - a temporary access link, whose issuing authorizes the launch but puts
//     no moderator in front of it.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// moderationRequired answers a launch that has to wait for its moderator. The
// header and the flag are the route-based gate's, so a client that handles
// one handles both.
func moderationRequired(c *gin.Context, entryID string) {
	c.Header("X-Moderation-Required", "true")
	c.JSON(http.StatusPreconditionRequired, gin.H{
		"error":               "a moderator must join before this session can start",
		"code":                "moderation_required",
		"moderation_required": true,
		"entry_id":            entryID,
	})
}

// moderationReadyPredicate is the moderation a launch may spend: one a
// moderator joined for this user on this entry, within the wait window, and no
// launch spent yet.
const moderationReadyPredicate = `entry_id = $1 AND requester_id = $2::uuid AND org_id = $3
	   AND status = 'active' AND admitted_at IS NULL
	   AND joined_at > NOW() - make_interval(secs => $4::bigint)`

// refuseUnmoderatedLaunch answers 428 for a launch of an entry that requires a
// moderator when no moderator has joined for the caller. It spends nothing:
// asked before the approval gate, it keeps a launch that has to wait from
// spending an approval. Reports true once it has answered.
func (s *Service) refuseUnmoderatedLaunch(c *gin.Context, orgID string, entry *pamLaunchEntry, userID string) bool {
	if !entry.RequireModerator {
		return false
	}
	var ready bool
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM guacamole_moderation_sessions WHERE `+moderationReadyPredicate+`)`,
		entry.ID, userID, orgID, int64(moderationWaitWindow.Seconds())).Scan(&ready); err != nil {
		s.logger.Error("moderation gate: lookup failed", zap.String("entry_id", logsafe.Clean(entry.ID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check the session's moderation"})
		return true
	}
	if !ready {
		moderationRequired(c, entry.ID)
		return true
	}
	return false
}

// claimPamModeration spends the moderation that admits this launch, in the
// statement that finds it: the row is locked as it is chosen, and a launch
// running beside this one skips it, so two launches cannot both spend one. It
// records the moderation on entry for the session row. Reports false once it
// has answered, for a moderation another launch spent first.
func (s *Service) claimPamModeration(c *gin.Context, orgID string, entry *pamLaunchEntry, userID string) bool {
	if !entry.RequireModerator {
		return true
	}
	err := s.db.Pool.QueryRow(c.Request.Context(), `
		UPDATE guacamole_moderation_sessions SET admitted_at = NOW()
		 WHERE id = (SELECT id FROM guacamole_moderation_sessions
		              WHERE `+moderationReadyPredicate+`
		              ORDER BY joined_at DESC LIMIT 1
		              FOR UPDATE SKIP LOCKED)
		RETURNING id::text`,
		entry.ID, userID, orgID, int64(moderationWaitWindow.Seconds())).Scan(&entry.ModerationID)
	if errors.Is(err, pgx.ErrNoRows) {
		moderationRequired(c, entry.ID)
		return false
	}
	if err != nil {
		s.logger.Error("moderation gate: claim failed", zap.String("entry_id", logsafe.Clean(entry.ID)), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check the session's moderation"})
		return false
	}
	return true
}

// releasePamModeration gives back a moderation whose launch failed, so the
// user can try again while their moderator is still there. A moderation a
// session row already names stays spent.
func (s *Service) releasePamModeration(orgID string, entry *pamLaunchEntry) {
	if entry.ModerationID == "" {
		return
	}
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: orgID})
	if _, err := s.db.Pool.Exec(ctx, `
		UPDATE guacamole_moderation_sessions m SET admitted_at = NULL
		 WHERE m.id = $1 AND m.org_id = $2
		   AND NOT EXISTS (SELECT 1 FROM pam_entry_sessions s WHERE s.moderation_id = m.id AND s.org_id = m.org_id)`,
		entry.ModerationID, orgID); err != nil {
		s.logger.Warn("moderation gate: could not give back the moderation of a failed launch",
			zap.String("moderation_id", logsafe.Clean(entry.ModerationID)), zap.Error(err))
	}
	entry.ModerationID = ""
}

// refuseModeratedEntry answers 403 on a launch path that runs no session a
// moderator could watch, for an entry that requires one. Reports true once it
// has answered.
func refuseModeratedEntry(c *gin.Context, entry *pamLaunchEntry, path string) bool {
	if !entry.RequireModerator {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{
		"error": "this entry's sessions are moderated, and " + path +
			" runs no session a moderator can watch: connect through the session broker",
		"code": "moderated_entry_needs_broker",
	})
	return true
}

// refuseRecordedEntry answers for a path that records nothing (the browser
// terminal, an SSH certificate) when the entry says its sessions are
// recorded. The setting is a promise about every session on the entry, and
// these paths opened sessions it never covered: only the session broker
// records. An external user is refused these paths whatever the entry says
// (I5); this is the same rule for everyone else, on an entry that asks for it.
func refuseRecordedEntry(c *gin.Context, recorded bool, path string) bool {
	if !recorded {
		return false
	}
	c.JSON(http.StatusForbidden, gin.H{
		"error": "this entry's sessions are recorded, and " + path +
			" records nothing: connect through the session broker",
		"code": "recorded_entry_needs_broker",
	})
	return true
}

// requestEntryModeration opens, or hands back, the caller's moderation request
// for a PAM entry that requires a moderator. The caller must be one who may
// connect to the entry: anyone else is told it does not exist. An external
// user's request is told to their sponsor, who may moderate it.
func (s *Service) requestEntryModeration(c *gin.Context, body moderationRequestBody) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	caller, ok := s.resolvePamCaller(c, org.ID)
	if !ok {
		return // resolvePamCaller already wrote the error
	}
	var name string
	var required bool
	err = s.db.Pool.QueryRow(ctx,
		`SELECT name, require_moderator FROM pam_entries WHERE id::text = $1 AND org_id = $2`,
		body.EntryID, org.ID).Scan(&name, &required)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
		return
	}
	if err != nil {
		s.logger.Error("requestEntryModeration: entry lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open moderation request"})
		return
	}
	if !caller.Admin {
		allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, body.EntryID, caller.UserID, pamCallerRoles(c), "connect")
		if aclErr != nil {
			s.logger.Error("requestEntryModeration: ACL check failed", zap.Error(aclErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
			return
		}
		if !allowed {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
			return
		}
	}
	if s.refuseClosedTarget(c, org.ID, caller, body.EntryID) {
		return
	}
	if !required {
		c.JSON(http.StatusConflict, gin.H{
			"error": "this entry does not require a moderator; connect to it directly",
			"code":  "moderation_not_required",
		})
		return
	}

	// A request still waiting for its moderator, or one a moderator joined
	// that no launch has spent, is handed back rather than doubled.
	var existingID, existingStatus string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id::text, status FROM guacamole_moderation_sessions
		 WHERE entry_id = $1 AND requester_id = $2::uuid AND org_id = $3 AND admitted_at IS NULL
		   AND ((status = 'pending' AND (expires_at IS NULL OR expires_at > NOW()))
		     OR (status = 'active' AND joined_at > NOW() - make_interval(secs => $4::bigint)))
		 ORDER BY created_at DESC LIMIT 1`,
		body.EntryID, caller.UserID, org.ID, int64(moderationWaitWindow.Seconds())).Scan(&existingID, &existingStatus)
	if err == nil {
		c.JSON(http.StatusOK, gin.H{"id": existingID, "status": existingStatus, "reused": true})
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("requestEntryModeration: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open moderation request"})
		return
	}

	expiresAt := time.Now().Add(moderationWaitWindow)
	var id string
	if err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO guacamole_moderation_sessions (org_id, entry_id, requester_id, reason, status, expires_at)
		VALUES ($1, $2, $3::uuid, NULLIF($4,''), 'pending', $5)
		RETURNING id::text`,
		org.ID, body.EntryID, caller.UserID, body.Reason, expiresAt).Scan(&id); err != nil {
		s.logger.Error("requestEntryModeration: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open moderation request"})
		return
	}
	s.logAuditEvent(c, "pam.moderation.requested", id, "moderation_session", map[string]interface{}{
		"entry_id": body.EntryID, "requester_id": caller.UserID, "reason": body.Reason, "external": caller.External,
	})
	if caller.External {
		s.notifySponsorOfModeration(ctx, org.ID, caller.UserID, body.EntryID, name, id)
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": "pending", "expires_at": expiresAt})
}

// SponsoredModeration is a moderation request of an external user, as their
// sponsor sees it.
type SponsoredModeration struct {
	ID        string     `json:"id"`
	EntryID   string     `json:"entry_id"`
	EntryName string     `json:"entry_name"`
	UserID    string     `json:"user_id"`
	User      string     `json:"user"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// handlePamListSponsoredModeration — GET /pam/sponsored/moderation: the
// pending moderation requests of the external users the caller sponsors.
// Empty for anyone who sponsors no one.
func (s *Service) handlePamListSponsoredModeration(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT m.id::text, m.entry_id::text, e.name, m.requester_id::text, COALESCE(NULLIF(u.email, ''), u.username),
		       COALESCE(m.reason, ''), m.created_at, m.expires_at
		  FROM guacamole_moderation_sessions m
		  JOIN pam_entries e ON e.id = m.entry_id AND e.org_id = m.org_id
		  JOIN users u ON u.id = m.requester_id AND u.org_id = m.org_id
		 WHERE m.org_id = $1 AND m.status = 'pending' AND (m.expires_at IS NULL OR m.expires_at > NOW())
		   AND u.user_type = 'external' AND u.sponsor_user_id = NULLIF($2,'')::uuid
		 ORDER BY m.created_at`, org.ID, c.GetString("user_id"))
	if err != nil {
		s.logger.Error("handlePamListSponsoredModeration: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list moderation requests"})
		return
	}
	defer rows.Close()
	out := []SponsoredModeration{}
	for rows.Next() {
		var m SponsoredModeration
		if err := rows.Scan(&m.ID, &m.EntryID, &m.EntryName, &m.UserID, &m.User, &m.Reason, &m.CreatedAt, &m.ExpiresAt); err != nil {
			s.logger.Error("handlePamListSponsoredModeration: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list moderation requests"})
			return
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("handlePamListSponsoredModeration: rows failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list moderation requests"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pending": out})
}

// handlePamSponsorJoinModeration — POST /pam/sponsored/moderation/:id/join:
// the sponsor of an external user joins as the moderator of their PAM entry
// session. A request that is not one of the caller's external users', or not
// pending, is not found. Atomic, as the administrator's join.
func (s *Service) handlePamSponsorJoinModeration(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	sponsorID := c.GetString("user_id")
	var requesterID, entryID string
	err = s.db.Pool.QueryRow(ctx, `
		UPDATE guacamole_moderation_sessions m
		   SET status = 'active', moderator_id = NULLIF($2,'')::uuid, joined_at = NOW()
		 WHERE m.id::text = $1 AND m.org_id = $3 AND m.status = 'pending' AND m.entry_id IS NOT NULL
		   AND (m.expires_at IS NULL OR m.expires_at > NOW())
		   AND m.requester_id <> NULLIF($2,'')::uuid
		   AND EXISTS (SELECT 1 FROM users u
		                WHERE u.id = m.requester_id AND u.org_id = m.org_id AND u.user_type = 'external'
		                  AND u.sponsor_user_id = NULLIF($2,'')::uuid)
		RETURNING m.requester_id::text, m.entry_id::text`,
		c.Param("id"), sponsorID, org.ID).Scan(&requesterID, &entryID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "moderation request not found or not pending"})
		return
	}
	if err != nil {
		s.logger.Error("handlePamSponsorJoinModeration: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to join moderation"})
		return
	}
	s.logAuditEvent(c, "pam.moderation.joined", c.Param("id"), "moderation_session", map[string]interface{}{
		"moderator_id": sponsorID, "requester_id": requesterID, "entry_id": entryID, "as": "sponsor",
	})
	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "status": "active", "moderator_id": sponsorID})
}

// handleWatchModeratedSession — POST /pam/moderation/:id/watch: the moderator
// of an entry moderation watches the session it admitted, read-only. Anyone
// else, and a moderation with no live session, is not found.
func (s *Service) handleWatchModeratedSession(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var row pamSessionRow
	var entryID, userID string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT s.id::text, COALESCE(s.guac_connection_id, ''), COALESCE(s.guac_username, ''), COALESCE(e.reach_mode, ''),
		       s.entry_id::text, s.user_id::text
		  FROM guacamole_moderation_sessions m
		  JOIN pam_entry_sessions s ON s.moderation_id = m.id AND s.org_id = m.org_id AND s.status = 'active'
		  JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		 WHERE m.id::text = $1 AND m.org_id = $2 AND m.status = 'active'
		   AND m.moderator_id = NULLIF($3,'')::uuid`,
		c.Param("id"), org.ID, c.GetString("user_id")).Scan(&row.rowID, &row.connID, &row.guacUser, &row.reach, &entryID, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "no live session you moderate here"})
		return
	}
	if err != nil {
		s.logger.Error("handleWatchModeratedSession: lookup failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load the session"})
		return
	}
	shareURL, ok := s.shareLiveSession(c, org.ID, row)
	if !ok {
		return // shareLiveSession already wrote the error
	}
	s.logAuditEvent(c, "pam.session_watched", row.rowID, "pam_entry_session", map[string]interface{}{
		"session_id": row.rowID, "entry_id": entryID, "user_id": userID, "read_only": true, "as": "moderator",
		"moderation_id": c.Param("id"),
	})
	c.JSON(http.StatusOK, gin.H{"share_url": shareURL, "read_only": true})
}

// endModeratedSessions ends, on their broker, the live sessions a moderation
// admitted, now that it has ended. A session the broker still serves is left
// to the lifecycle sweep, which ends a session whose moderation ended.
func (s *Service) endModeratedSessions(c *gin.Context, orgID, moderationID, actor string) {
	ctx := c.Request.Context()
	rows, err := s.db.Pool.Query(ctx, `
		SELECT s.id, COALESCE(s.guac_connection_id, ''), COALESCE(s.guac_username, ''), COALESCE(e.reach_mode, '')
		  FROM pam_entry_sessions s
		  JOIN pam_entries e ON e.id = s.entry_id AND e.org_id = s.org_id
		 WHERE s.moderation_id = $1::uuid AND s.org_id = $2 AND s.status = 'active'`, moderationID, orgID)
	if err != nil {
		s.logger.Warn("moderation end: listing the sessions it admitted failed; the lifecycle sweep ends them",
			zap.Error(err))
		return
	}
	warn := func(step string, err error) {
		s.logger.Warn("moderation end: a session it admitted was not ended (the lifecycle sweep retries)",
			zap.String("step", step), zap.String("moderation_id", logsafe.Clean(moderationID)), zap.Error(err))
	}
	for _, id := range s.endPamEntrySessionRows(ctx, orgID, scanPamSessionRows(rows), warn) {
		s.logAuditEvent(c, "pam.session_ended", id, "pam_entry_session", map[string]interface{}{
			"session_id": id, "moderation_id": moderationID, "reason": sessionEndModeration,
		})
		s.pamSessionEnded(orgID, id, sessionEndModeration, actor)
	}
}

// ModeratedSession is an active entry moderation the caller moderates, with
// whether the session it admitted is live.
type ModeratedSession struct {
	ID          string     `json:"id"`
	EntryID     string     `json:"entry_id"`
	EntryName   string     `json:"entry_name"`
	RequesterID string     `json:"requester_id"`
	Requester   string     `json:"requester"`
	JoinedAt    *time.Time `json:"joined_at,omitempty"`
	SessionLive bool       `json:"session_live"`
}

// handleListModerating — GET /pam/moderation/moderating: the entry
// moderations the caller joined and has not ended, so a moderator can watch
// the session once it starts, and end it.
func (s *Service) handleListModerating(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT m.id::text, m.entry_id::text, e.name, m.requester_id::text, COALESCE(NULLIF(u.email, ''), u.username, ''),
		       m.joined_at,
		       EXISTS (SELECT 1 FROM pam_entry_sessions s
		                WHERE s.moderation_id = m.id AND s.org_id = m.org_id AND s.status = 'active')
		  FROM guacamole_moderation_sessions m
		  JOIN pam_entries e ON e.id = m.entry_id AND e.org_id = m.org_id
		  LEFT JOIN users u ON u.id = m.requester_id AND u.org_id = m.org_id
		 WHERE m.org_id = $1 AND m.status = 'active' AND m.moderator_id = NULLIF($2,'')::uuid
		 ORDER BY m.joined_at DESC`, org.ID, c.GetString("user_id"))
	if err != nil {
		s.logger.Error("handleListModerating: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list moderated sessions"})
		return
	}
	defer rows.Close()
	out := []ModeratedSession{}
	for rows.Next() {
		var m ModeratedSession
		if err := rows.Scan(&m.ID, &m.EntryID, &m.EntryName, &m.RequesterID, &m.Requester, &m.JoinedAt, &m.SessionLive); err != nil {
			s.logger.Error("handleListModerating: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list moderated sessions"})
			return
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("handleListModerating: rows failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list moderated sessions"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"moderations": out})
}
