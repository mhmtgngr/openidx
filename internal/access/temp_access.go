// Temporary access links, retired (Phase 3, D2).
//
// A temporary access link was an anonymous URL that put whoever held it onto
// a PAM entry's session: no identity, no second factor, no sponsor, nothing
// but the token. The vendor framework replaced it -- a vendor's people are
// external users with their own factor, reaching only what a running
// engagement covers, approved by and visible to their sponsor -- so the link
// is no longer issued and no longer redeems. What is left is the history:
// administrators can still list the links that were issued, read their use,
// and revoke one, so the record survives until the table is exported and
// dropped. A link opened now gets a page that says how access works instead.
package access

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// TempAccessLink represents a temporary access link for support/vendor access
type TempAccessLink struct {
	ID               string     `json:"id"`
	Token            string     `json:"token"`
	Name             string     `json:"name"`
	Description      string     `json:"description,omitempty"`
	PamEntryID       string     `json:"pam_entry_id,omitempty"`
	Protocol         string     `json:"protocol"` // ssh, rdp, vnc
	TargetHost       string     `json:"target_host"`
	TargetPort       int        `json:"target_port"`
	Username         string     `json:"username,omitempty"`
	CreatedBy        string     `json:"created_by"`
	CreatedByEmail   string     `json:"created_by_email"`
	ExpiresAt        time.Time  `json:"expires_at"`
	MaxUses          int        `json:"max_uses"` // 0 = unlimited
	CurrentUses      int        `json:"current_uses"`
	AllowedIPs       []string   `json:"allowed_ips,omitempty"` // IP whitelist
	NotifyOnUse      bool       `json:"notify_on_use"`
	RouteID          string     `json:"route_id,omitempty"`
	GuacConnectionID string     `json:"guacamole_connection_id,omitempty"`
	AccessURL        string     `json:"access_url"`
	Status           string     `json:"status"` // active, expired, revoked, used
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP       string     `json:"last_used_ip,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// TempAccessUsage tracks usage of temporary access links
type TempAccessUsage struct {
	ID             string     `json:"id"`
	LinkID         string     `json:"link_id"`
	IPAddress      string     `json:"ip_address"`
	UserAgent      string     `json:"user_agent"`
	ConnectedAt    time.Time  `json:"connected_at"`
	DisconnectedAt *time.Time `json:"disconnected_at,omitempty"`
	Duration       int        `json:"duration_seconds,omitempty"`
}

// handleListTempAccess lists all temporary access links
func (s *Service) handleListTempAccess(c *gin.Context) {
	status := c.DefaultQuery("status", "")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	query := `
		SELECT id, token, name, description, COALESCE(pam_entry_id::text,''), protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, notify_on_use, route_id,
			guacamole_connection_id, access_url, status, last_used_at, last_used_ip,
			created_at, updated_at
		FROM temp_access_links
		WHERE org_id = $2 AND ($1 = '' OR status = $1)
		ORDER BY created_at DESC
		LIMIT 100`

	rows, err := s.db.Pool.Query(c.Request.Context(), query, status, org.ID)
	if err != nil {
		s.logger.Error("failed to list temp access links", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list access links"})
		return
	}
	defer rows.Close()

	var links []TempAccessLink
	for rows.Next() {
		var link TempAccessLink
		err := rows.Scan(
			&link.ID, &link.Token, &link.Name, &link.Description, &link.PamEntryID, &link.Protocol,
			&link.TargetHost, &link.TargetPort, &link.Username, &link.CreatedBy,
			&link.CreatedByEmail, &link.ExpiresAt, &link.MaxUses, &link.CurrentUses,
			&link.AllowedIPs, &link.NotifyOnUse,
			&link.RouteID, &link.GuacConnectionID, &link.AccessURL, &link.Status,
			&link.LastUsedAt, &link.LastUsedIP, &link.CreatedAt, &link.UpdatedAt,
		)
		if err != nil {
			continue
		}

		// Auto-expire if past expiration
		if time.Now().After(link.ExpiresAt) && link.Status == "active" {
			link.Status = "expired"
		}

		// Mask token for security (only show first 8 chars)
		if len(link.Token) > 8 {
			link.Token = link.Token[:8] + "..."
		}

		links = append(links, link)
	}

	c.JSON(http.StatusOK, gin.H{"links": links})
}

// handleGetTempAccess gets a specific temp access link
func (s *Service) handleGetTempAccess(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	query := `
		SELECT id, token, name, description, COALESCE(pam_entry_id::text,''), protocol, target_host, target_port, username,
			created_by, created_by_email, expires_at, max_uses, current_uses,
			allowed_ips, notify_on_use, route_id,
			guacamole_connection_id, access_url, status, last_used_at, last_used_ip,
			created_at, updated_at
		FROM temp_access_links
		WHERE id = $1 AND org_id = $2`

	var link TempAccessLink
	err = s.db.Pool.QueryRow(c.Request.Context(), query, id, org.ID).Scan(
		&link.ID, &link.Token, &link.Name, &link.Description, &link.PamEntryID, &link.Protocol,
		&link.TargetHost, &link.TargetPort, &link.Username, &link.CreatedBy,
		&link.CreatedByEmail, &link.ExpiresAt, &link.MaxUses, &link.CurrentUses,
		&link.AllowedIPs, &link.NotifyOnUse,
		&link.RouteID, &link.GuacConnectionID, &link.AccessURL, &link.Status,
		&link.LastUsedAt, &link.LastUsedIP, &link.CreatedAt, &link.UpdatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	c.JSON(http.StatusOK, link)
}

// handleRevokeTempAccess revokes a temp access link
func (s *Service) handleRevokeTempAccess(c *gin.Context) {
	id := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	query := `UPDATE temp_access_links SET status = 'revoked', updated_at = $1 WHERE id = $2 AND org_id = $3`
	result, err := s.db.Pool.Exec(c.Request.Context(), query, time.Now(), id, org.ID)
	if err != nil {
		s.logger.Error("failed to revoke temp access link", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke access link"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	s.recordUnifiedEvent(c, org.ID, "temp_access.revoked", c.GetString("user_id"), id, "temp_access_link",
		map[string]interface{}{"link_id": id})

	c.JSON(http.StatusOK, gin.H{"message": "access link revoked"})
}

// handleRetiredTempAccess — GET /temp-access/:token. Links no longer redeem.
// The page is the same for every token and reads nothing: whether a token was
// ever issued is not the visitor's to learn.
func (s *Service) handleRetiredTempAccess(c *gin.Context) {
	renderTempAccessError(c, http.StatusGone, "Temporary Access Links Are Retired",
		"This kind of link no longer opens a session. Ask the person who sent it for access as a "+
			"vendor user: you sign in with your own account, and you reach what your engagement covers.")
}

// renderTempAccessError writes a plain page directly rather than through
// c.HTML: nothing in this repository registers a template renderer, so c.HTML
// would dereference a nil renderer and panic. Both values are escaped.
func renderTempAccessError(c *gin.Context, status int, title, message string) {
	page := fmt.Sprintf(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
 body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1f2933;
      background:#f5f7fa;margin:0;display:flex;min-height:100vh;
      align-items:center;justify-content:center;padding:24px}
 main{background:#fff;border:1px solid #d9e2ec;border-radius:12px;
      padding:32px;max-width:34rem}
 h1{font-size:1.25rem;margin:0 0 12px}
 p{margin:0;color:#3e4c59}
</style></head>
<body><main><h1>%s</h1><p>%s</p></main></body></html>
`, template.HTMLEscapeString(title), template.HTMLEscapeString(title),
		template.HTMLEscapeString(message))
	c.Data(status, "text/html; charset=utf-8", []byte(page))
}

// handleGetTempAccessUsage gets usage history for a temp access link
func (s *Service) handleGetTempAccessUsage(c *gin.Context) {
	linkID := c.Param("id")

	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization context required"})
		return
	}

	// Verify the link belongs to the caller's org, so a cross-org id gets the
	// same 404 as an id that does not exist rather than an empty history.
	var ok bool
	if err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM temp_access_links WHERE id = $1 AND org_id = $2)`, linkID, org.ID).Scan(&ok); err != nil || !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "access link not found"})
		return
	}

	// The org predicate below is not redundant with that check. Until v148 this
	// query read `WHERE link_id = $1` alone and was safe only because the
	// statement above happened to run first — safety living in the order two
	// statements are written in, which is the shape v143 and v147 both found
	// recorded as though it were a property of the schema. The check above
	// proves the LINK is the caller's; only this predicate proves the ROWS are.
	query := `
		SELECT id, link_id, ip_address, user_agent, connected_at, disconnected_at
		FROM temp_access_usage
		WHERE link_id = $1 AND org_id = $2
		ORDER BY connected_at DESC
		LIMIT 50`

	rows, err := s.db.Pool.Query(c.Request.Context(), query, linkID, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get usage history"})
		return
	}
	defer rows.Close()

	var usage []TempAccessUsage
	for rows.Next() {
		var u TempAccessUsage
		err := rows.Scan(&u.ID, &u.LinkID, &u.IPAddress, &u.UserAgent, &u.ConnectedAt, &u.DisconnectedAt)
		if err != nil {
			continue
		}
		if u.DisconnectedAt != nil {
			u.Duration = int(u.DisconnectedAt.Sub(u.ConnectedAt).Seconds())
		}
		usage = append(usage, u)
	}

	c.JSON(http.StatusOK, gin.H{"usage": usage})
}

// recordUnifiedEvent writes an access-service event to the unified audit trail
// under the given tenant, or the request's when none is given. The temporary
// access events are its reason to exist; the Guacamole legal-hold events had
// the same log-only helper and ride it too.
//
// Until this existed every temp_access.* event was a zap log line with a
// comment saying an implementation "would send to audit service". The link is
// the one feature in the product that lets an outside party onto an internal
// host, and the console's Unified Audit page, the compliance reports and the
// HMAC chain never saw it issued, used, refused or revoked. The usage table
// recorded the connections; nothing recorded the refusals at all.
//
// The tenant is the LINK'S. A redemption arrives with no session and no
// organization on the context (the vendor is anonymous), so the row is
// written under the org the token resolved to, the same way the usage row
// is, and the bypass is the redemption path's own (v148). The actor is the
// issuer or the revoking administrator when there is one and nobody when
// there is not; the redeemer is known by address, user agent and the link.
//
// An audit write must never fail the thing it records, so a failure is logged
// at error level with the event it lost rather than returned. An access
// service built without a unified audit store (tests) logs the event instead
// and says so.
func (s *Service) recordUnifiedEvent(c *gin.Context, orgID, eventType, actorUserID, targetID, targetType string, details map[string]interface{}) {
	if orgID == "" {
		if org, err := orgctx.From(c.Request.Context()); err == nil {
			orgID = org.ID
		}
	}
	clientIP := c.ClientIP()
	// The details carry what the request said about itself (its address, its
	// user agent, the code a launch failed with), so what reaches the log is
	// scrubbed the way every other param-derived field in this package is.
	detailsJSON := ""
	if b, err := json.Marshal(details); err == nil {
		detailsJSON = string(b)
	}
	if s.auditService == nil {
		s.logger.Warn("temp access: no unified audit store, event not recorded",
			zap.String("event_type", eventType), logsafe.String("target_id", targetID),
			logsafe.String("details", detailsJSON), logsafe.String("ip", clientIP))
		return
	}
	ctx := orgctx.WithBypassRLS(orgctx.With(c.Request.Context(), orgctx.Org{ID: orgID}))
	if err := s.auditService.RecordEvent(ctx, "openidx", eventType, "", actorUserID, clientIP, details); err != nil {
		s.logger.Error("temp access: unified audit write failed",
			zap.String("event_type", eventType), logsafe.String("target_id", targetID),
			logsafe.String("details", detailsJSON), logsafe.String("ip", clientIP), zap.Error(err))
	}
	// The management events have an authenticated actor and an organization
	// on the request, so they also go to the audit service's own stream, as
	// every other administrative action in this package does. The anonymous
	// redemption events do not: that stream resolves the tenant from the
	// request, which for a vendor's browser would be the default organization.
	if actorUserID != "" {
		s.logAuditEvent(c, eventType, targetID, targetType, details)
	}
}
