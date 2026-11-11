package access

// Sites (migration 249): where applications live and edge routers run. This
// file is the API over the sites table (list, create, rename) and the one
// resolver every writer of a site_id uses, so a slug is validated the same way
// on a network target, a published app and a router enrollment.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// siteSlugPattern mirrors the CHECK constraint on sites.slug.
var siteSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)

// errUnknownSite is a slug with no sites row.
var errUnknownSite = errors.New("unknown site")

// siteView is one site as the API returns it.
type siteView struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	HopAddr     string    `json:"hop_addr"`
	IsDefault   bool      `json:"is_default"`
	Routers     int       `json:"routers"`
	CreatedAt   time.Time `json:"created_at"`
}

// resolveSiteID turns a slug into the value a site_id column takes: nil for
// the default site (NULL means default, so the default is never written by id)
// and the site's id otherwise. An unknown or malformed slug is errUnknownSite.
func (s *Service) resolveSiteID(ctx context.Context, slug string) (interface{}, error) {
	slug = strings.TrimSpace(slug)
	if isDefaultSite(slug) {
		return nil, nil
	}
	if !siteSlugPattern.MatchString(slug) {
		return nil, fmt.Errorf("%w %q", errUnknownSite, slug)
	}
	var id string
	var isDefault bool
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		//orgscope:ignore install-wide platform table; sites has no org
		`SELECT id::text, is_default FROM sites WHERE slug = $1`, slug).Scan(&id, &isDefault)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w %q", errUnknownSite, slug)
	}
	if err != nil {
		return nil, err
	}
	if isDefault {
		return nil, nil
	}
	return id, nil
}

// handleListSites lists every site with its router count. Sites are
// install-wide; any admin may read them to choose one for a resource.
func (s *Service) handleListSites(c *gin.Context) {
	rows, err := s.db.Pool.Query(orgctx.WithBypassRLS(c.Request.Context()),
		//orgscope:ignore install-wide platform table; sites has no org
		`SELECT s.id::text, s.slug, s.name, s.description, COALESCE(s.hop_addr, ''), s.is_default,
		        (SELECT count(*) FROM site_routers sr WHERE sr.site_id = s.id)::int, s.created_at
		   FROM sites s ORDER BY s.is_default DESC, s.slug`)
	if err != nil {
		s.logger.Error("list sites", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sites"})
		return
	}
	defer rows.Close()
	out := []siteView{}
	for rows.Next() {
		var v siteView
		if err := rows.Scan(&v.ID, &v.Slug, &v.Name, &v.Description, &v.HopAddr, &v.IsDefault, &v.Routers, &v.CreatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sites"})
			return
		}
		out = append(out, v)
	}
	if rows.Err() != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sites"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sites": out, "total": len(out)})
}

type siteWrite struct {
	Slug        *string `json:"slug"`
	Name        *string `json:"name"`
	Description *string `json:"description"`
	HopAddr     *string `json:"hop_addr"`
}

// handleCreateSite creates a site. The default site exists from migration 249
// and cannot be created again.
func (s *Service) handleCreateSite(c *gin.Context) {
	var req siteWrite
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	slug, name := "", ""
	if req.Slug != nil {
		slug = strings.TrimSpace(*req.Slug)
	}
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if !siteSlugPattern.MatchString(slug) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "slug must be 1-39 lowercase letters, digits or hyphens, starting with a letter or digit"})
		return
	}
	if name == "" {
		name = slug
	}
	if len(name) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is at most 255 characters"})
		return
	}
	desc, hop := "", ""
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	var hopArg interface{}
	if req.HopAddr != nil && strings.TrimSpace(*req.HopAddr) != "" {
		hop = strings.TrimSpace(*req.HopAddr)
		hopArg = hop
	}
	var v siteView
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(c.Request.Context()),
		//orgscope:ignore install-wide platform table; sites has no org
		`INSERT INTO sites (slug, name, description, hop_addr) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (slug) DO NOTHING
		 RETURNING id::text, slug, name, description, COALESCE(hop_addr, ''), is_default, created_at`,
		slug, name, desc, hopArg).Scan(&v.ID, &v.Slug, &v.Name, &v.Description, &v.HopAddr, &v.IsDefault, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusConflict, gin.H{"error": "a site with this slug already exists"})
		return
	}
	if err != nil {
		s.logger.Error("create site", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create site"})
		return
	}
	s.logAuditEvent(c, "site.create", v.ID, "site", map[string]interface{}{"slug": slug})
	c.JSON(http.StatusCreated, v)
}

// handlePatchSite renames a site or edits its description and hop address.
// The slug is not editable: routers carry it as their site-<slug> attribute
// and services bind to #site-<slug>, so renaming it would orphan both.
func (s *Service) handlePatchSite(c *gin.Context) {
	var req siteWrite
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Slug != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a site's slug cannot be changed; routers and services are bound to it"})
		return
	}
	id := c.Param("id")
	var name, desc, hop interface{}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n == "" || len(n) > 255 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name is required (at most 255 characters)"})
			return
		}
		name = n
	}
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	clearHop := false
	if req.HopAddr != nil {
		if h := strings.TrimSpace(*req.HopAddr); h != "" {
			hop = h
		} else {
			clearHop = true
		}
	}
	var v siteView
	err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(c.Request.Context()),
		//orgscope:ignore install-wide platform table; sites has no org
		`UPDATE sites SET name = COALESCE($2::text, name), description = COALESCE($3::text, description),
		        hop_addr = CASE WHEN $5::boolean THEN NULL ELSE COALESCE($4::text, hop_addr) END, updated_at = NOW()
		  WHERE id::text = $1
		 RETURNING id::text, slug, name, description, COALESCE(hop_addr, ''), is_default, created_at`,
		id, name, desc, hop, clearHop).Scan(&v.ID, &v.Slug, &v.Name, &v.Description, &v.HopAddr, &v.IsDefault, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "site not found"})
		return
	}
	if err != nil {
		s.logger.Error("patch site", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update site"})
		return
	}
	s.logAuditEvent(c, "site.update", v.ID, "site", map[string]interface{}{"slug": v.Slug})
	c.JSON(http.StatusOK, v)
}
