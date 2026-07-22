// Package access — Quick Links: an admin-curated, user-searchable launcher for
// support/collaboration systems.
//
// A quick link is either:
//   - type='external' — a plain URL (Teams, Zoom, status page, ticketing, docs)
//     the browser opens directly; or
//   - type='pam'      — a reference to a pam_entries row; the user page launches
//     it CLIENTLESSLY through that entry's renderer (guacamole tab or the
//     in-browser wasm-ssh terminal). No connection config is duplicated and the
//     PAM permission/approval gate still applies when the entry is launched.
//
// Admin CRUD is under /api/v1/access/quick-links (requireAdminRole); the
// user-facing read is /api/v1/access/quick-links/my, role-filtered by min_role.
package access

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// quickLink is a row of the quick_links table (also the API shape).
type quickLink struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Icon        string `json:"icon"`
	Type        string `json:"type"` // external | pam
	URL         string `json:"url,omitempty"`
	PamEntryID  string `json:"pam_entry_id,omitempty"`
	PamRenderer string `json:"pam_renderer,omitempty"` // resolved for pam links (guacamole|wasm-ssh)
	MinRole     string `json:"min_role"`
	SortOrder   int    `json:"sort_order"`
	Enabled     bool   `json:"enabled"`
	OpenInNew   bool   `json:"open_in_new"`
}

// quickLinkUpsertReq is the create/update body.
type quickLinkUpsertReq struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Icon        string `json:"icon"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	PamEntryID  string `json:"pam_entry_id"`
	MinRole     string `json:"min_role"`
	SortOrder   int    `json:"sort_order"`
	Enabled     *bool  `json:"enabled"`
	OpenInNew   *bool  `json:"open_in_new"`
}

// roleRank is the hierarchical order used by min_role filtering. A caller sees a
// link when their highest role rank >= the link's min_role rank.
var quickLinkRoleRank = map[string]int{
	"user": 0, "auditor": 1, "operator": 2, "admin": 3, "super_admin": 4,
}

func quickLinkRank(role string) int {
	if r, ok := quickLinkRoleRank[role]; ok {
		return r
	}
	return 0
}

// callerMaxRank returns the caller's highest role rank (dev mode = super_admin).
func (s *Service) callerMaxRank(c *gin.Context) int {
	if s.config != nil && s.config.IsDevelopment() {
		return quickLinkRank("super_admin")
	}
	max := 0
	for _, r := range pamCallerRoles(c) {
		if rr := quickLinkRank(r); rr > max {
			max = rr
		}
	}
	return max
}

// validQuickLinkURL allows only safe external schemes (never javascript:/data:).
func validQuickLinkURL(u string) bool {
	l := strings.ToLower(strings.TrimSpace(u))
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") ||
		strings.HasPrefix(l, "mailto:") || strings.HasPrefix(l, "tel:")
}

func normalizeQuickLinkRole(role string) string {
	if _, ok := quickLinkRoleRank[role]; ok {
		return role
	}
	return "user"
}

// handleListQuickLinks (admin) — GET /quick-links. All links for the org.
func (s *Service) handleListQuickLinks(c *gin.Context) {
	s.listQuickLinks(c, false)
}

// handleMyQuickLinks (any user) — GET /quick-links/my. Enabled links the
// caller's role satisfies, sorted for display.
func (s *Service) handleMyQuickLinks(c *gin.Context) {
	s.listQuickLinks(c, true)
}

func (s *Service) listQuickLinks(c *gin.Context, userScope bool) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT q.id, q.title, q.description, q.category, q.icon, q.type,
		       COALESCE(q.url,''), COALESCE(q.pam_entry_id::text,''),
		       COALESCE(pe.renderer,''), q.min_role, q.sort_order, q.enabled, q.open_in_new
		  FROM quick_links q
		  LEFT JOIN pam_entries pe ON pe.id = q.pam_entry_id
		 WHERE q.org_id = $1
		 ORDER BY q.sort_order ASC, q.title ASC`, org.ID)
	if err != nil {
		s.logger.Error("listQuickLinks: query failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load quick links"})
		return
	}
	defer rows.Close()

	maxRank := s.callerMaxRank(c)
	links := []quickLink{}
	for rows.Next() {
		var q quickLink
		if err := rows.Scan(&q.ID, &q.Title, &q.Description, &q.Category, &q.Icon, &q.Type,
			&q.URL, &q.PamEntryID, &q.PamRenderer, &q.MinRole, &q.SortOrder, &q.Enabled, &q.OpenInNew); err != nil {
			s.logger.Warn("listQuickLinks: scan failed", zap.Error(err))
			continue
		}
		if userScope {
			if !q.Enabled || quickLinkRank(q.MinRole) > maxRank {
				continue
			}
		}
		links = append(links, q)
	}
	c.JSON(http.StatusOK, gin.H{"quick_links": links})
}

// handleCreateQuickLink (admin) — POST /quick-links.
func (s *Service) handleCreateQuickLink(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req quickLinkUpsertReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := s.validateQuickLink(ctx, org.ID, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id := uuid.New().String()
	userID := c.GetString("user_id")
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO quick_links (id, org_id, title, description, category, icon, type, url,
		                         pam_entry_id, min_role, sort_order, enabled, open_in_new, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9,'')::uuid, $10, $11, $12, $13, NULLIF($14,'')::uuid)`,
		id, org.ID, req.Title, req.Description, quickLinkCategory(req.Category), quickLinkIcon(req.Icon),
		req.Type, req.URL, req.PamEntryID, normalizeQuickLinkRole(req.MinRole), req.SortOrder,
		boolOrDefault(req.Enabled, true), boolOrDefault(req.OpenInNew, true), userID); err != nil {
		s.logger.Error("handleCreateQuickLink: insert failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create quick link"})
		return
	}
	s.logAuditEvent(c, "quick_link.created", id, "quick_link", map[string]interface{}{
		"title": req.Title, "type": req.Type,
	})
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// handleUpdateQuickLink (admin) — PUT /quick-links/:id.
func (s *Service) handleUpdateQuickLink(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	var req quickLinkUpsertReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := s.validateQuickLink(ctx, org.ID, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE quick_links
		   SET title=$1, description=$2, category=$3, icon=$4, type=$5, url=$6,
		       pam_entry_id=NULLIF($7,'')::uuid, min_role=$8, sort_order=$9,
		       enabled=$10, open_in_new=$11, updated_at=NOW()
		 WHERE id=$12 AND org_id=$13`,
		req.Title, req.Description, quickLinkCategory(req.Category), quickLinkIcon(req.Icon),
		req.Type, req.URL, req.PamEntryID, normalizeQuickLinkRole(req.MinRole), req.SortOrder,
		boolOrDefault(req.Enabled, true), boolOrDefault(req.OpenInNew, true), id, org.ID)
	if err != nil {
		s.logger.Error("handleUpdateQuickLink: update failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update quick link"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "quick link not found"})
		return
	}
	s.logAuditEvent(c, "quick_link.updated", id, "quick_link", map[string]interface{}{"title": req.Title})
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// handleDeleteQuickLink (admin) — DELETE /quick-links/:id.
func (s *Service) handleDeleteQuickLink(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	tag, err := s.db.Pool.Exec(ctx, `DELETE FROM quick_links WHERE id=$1 AND org_id=$2`, id, org.ID)
	if err != nil {
		s.logger.Error("handleDeleteQuickLink: delete failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete quick link"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "quick link not found"})
		return
	}
	s.logAuditEvent(c, "quick_link.deleted", id, "quick_link", nil)
	c.Status(http.StatusNoContent)
}

// validateQuickLink enforces the type<->fields contract and safe URLs.
func (s *Service) validateQuickLink(ctx context.Context, orgID string, req *quickLinkUpsertReq) error {
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		return errQuickLink("title is required")
	}
	switch req.Type {
	case "external":
		if !validQuickLinkURL(req.URL) {
			return errQuickLink("a valid http(s)/mailto/tel URL is required")
		}
		req.PamEntryID = ""
	case "pam":
		if req.PamEntryID == "" {
			return errQuickLink("a PAM connection must be selected")
		}
		// Verify the referenced entry exists in this org.
		var exists bool
		_ = s.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pam_entries WHERE id=$1 AND org_id=$2)`,
			req.PamEntryID, orgID).Scan(&exists)
		if !exists {
			return errQuickLink("referenced PAM connection not found")
		}
		req.URL = ""
	default:
		return errQuickLink("type must be 'external' or 'pam'")
	}
	return nil
}

type quickLinkErr struct{ msg string }

func (e quickLinkErr) Error() string { return e.msg }
func errQuickLink(m string) error    { return quickLinkErr{m} }

func boolOrDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// quickLinkCategory/Icon default empties so the UI always has something to show.
func quickLinkCategory(c string) string {
	if strings.TrimSpace(c) == "" {
		return "Other"
	}
	return c
}
func quickLinkIcon(i string) string {
	if strings.TrimSpace(i) == "" {
		return "Link2"
	}
	return i
}
