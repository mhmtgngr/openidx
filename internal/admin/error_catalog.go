package admin

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ErrorCatalogEntry represents a documented error code
type ErrorCatalogEntry struct {
	Code             string    `json:"code"`
	HTTPStatus       int       `json:"http_status"`
	Category         string    `json:"category"`
	Description      string    `json:"description"`
	ResolutionHint   string    `json:"resolution_hint,omitempty"`
	DocumentationURL string    `json:"documentation_url,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (s *Service) handleListErrorCatalog(c *gin.Context) {
	ctx := c.Request.Context()
	category := c.Query("category")

	query := `SELECT code, http_status, category, description,
		COALESCE(resolution_hint, ''), COALESCE(documentation_url, ''),
		created_at, updated_at
		FROM error_catalog`
	args := []interface{}{}

	if category != "" {
		query += " WHERE category = $1"
		args = append(args, category)
	}
	query += " ORDER BY code"

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		s.logger.Error("failed to list error catalog", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list error catalog"})
		return
	}
	defer rows.Close()

	entries := []ErrorCatalogEntry{}
	for rows.Next() {
		var e ErrorCatalogEntry
		if err := rows.Scan(&e.Code, &e.HTTPStatus, &e.Category, &e.Description,
			&e.ResolutionHint, &e.DocumentationURL, &e.CreatedAt, &e.UpdatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	c.JSON(http.StatusOK, gin.H{"errors": entries, "total": len(entries)})
}

func (s *Service) handleCreateErrorCatalogEntry(c *gin.Context) {
	ctx := c.Request.Context()

	var req struct {
		Code             string `json:"code" binding:"required"`
		HTTPStatus       int    `json:"http_status" binding:"required"`
		Category         string `json:"category" binding:"required"`
		Description      string `json:"description" binding:"required"`
		ResolutionHint   string `json:"resolution_hint"`
		DocumentationURL string `json:"documentation_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `INSERT INTO error_catalog (code, http_status, category, description, resolution_hint, documentation_url)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (code) DO UPDATE SET
			http_status = EXCLUDED.http_status,
			category = EXCLUDED.category,
			description = EXCLUDED.description,
			resolution_hint = EXCLUDED.resolution_hint,
			documentation_url = EXCLUDED.documentation_url,
			updated_at = NOW()
		RETURNING created_at, updated_at`

	var createdAt, updatedAt time.Time
	err := s.db.Pool.QueryRow(ctx, query,
		req.Code, req.HTTPStatus, req.Category, req.Description,
		req.ResolutionHint, req.DocumentationURL,
	).Scan(&createdAt, &updatedAt)
	if err != nil {
		s.logger.Error("failed to create error catalog entry", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create entry"})
		return
	}

	c.JSON(http.StatusCreated, ErrorCatalogEntry{
		Code:             req.Code,
		HTTPStatus:       req.HTTPStatus,
		Category:         req.Category,
		Description:      req.Description,
		ResolutionHint:   req.ResolutionHint,
		DocumentationURL: req.DocumentationURL,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
	})
}

func (s *Service) handleUpdateErrorCatalogEntry(c *gin.Context) {
	ctx := c.Request.Context()
	code := c.Param("code")

	var req struct {
		HTTPStatus       int    `json:"http_status"`
		Category         string `json:"category"`
		Description      string `json:"description"`
		ResolutionHint   string `json:"resolution_hint"`
		DocumentationURL string `json:"documentation_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `UPDATE error_catalog SET
		http_status = $2, category = $3, description = $4,
		resolution_hint = $5, documentation_url = $6, updated_at = NOW()
		WHERE code = $1`

	result, err := s.db.Pool.Exec(ctx, query,
		code, req.HTTPStatus, req.Category, req.Description,
		req.ResolutionHint, req.DocumentationURL)
	if err != nil {
		s.logger.Error("failed to update error catalog entry", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update entry"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "error code not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (s *Service) handleDeleteErrorCatalogEntry(c *gin.Context) {
	ctx := c.Request.Context()
	code := c.Param("code")

	result, err := s.db.Pool.Exec(ctx, "DELETE FROM error_catalog WHERE code = $1", code)
	if err != nil {
		s.logger.Error("failed to delete error catalog entry", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete entry"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "error code not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}
