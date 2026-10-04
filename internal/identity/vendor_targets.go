package identity

// What is open to a vendor organization on a closed list: invariant I11 of
// the third-party access framework (migration v219). A target is a PAM entry,
// an application or a network service, named by id. With the vendor's
// closed_list on, its external users ask for and launch only these
// (internal/externalid.CheckTargetOpen); with it off, the list is kept but
// decides nothing. Administrator routes, like the rest of the vendor API; each
// change is audited.

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// VendorTarget is one target opened to a vendor organization.
type VendorTarget struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	TargetName string    `json:"target_name"`
	CreatedAt  time.Time `json:"created_at"`
}

// vendorForTargets reads the vendor organization named in the path, or
// answers 404. A closed vendor's list cannot change.
func (s *Service) vendorForTargets(c *gin.Context, orgID string, changing bool) bool {
	var status string
	err := s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT status FROM vendor_organizations WHERE id::text = $1 AND org_id = $2`, c.Param("id"), orgID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": errVendorOrgNotFound.Error()})
		return false
	}
	if err != nil {
		s.logger.Error("read vendor organization failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the vendor organization"})
		return false
	}
	if changing && status == "closed" {
		c.JSON(http.StatusConflict, gin.H{"error": "a closed vendor organization cannot be changed", "code": "vendor_org_closed"})
		return false
	}
	return true
}

// handleListVendorTargets — GET /vendor-orgs/:id/targets.
func (s *Service) handleListVendorTargets(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if !s.vendorForTargets(c, org.ID, false) {
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT t.id::text, t.target_type, t.target_id::text,
		       COALESCE(e.name, a.name, ''), t.created_at
		  FROM vendor_org_targets t
		  LEFT JOIN pam_entries e ON t.target_type = 'pam_entry' AND e.id = t.target_id AND e.org_id = t.org_id
		  LEFT JOIN applications a ON t.target_type = 'application' AND a.id = t.target_id AND a.org_id = t.org_id
		 WHERE t.vendor_org_id::text = $1 AND t.org_id = $2
		 ORDER BY t.created_at`, c.Param("id"), org.ID)
	if err != nil {
		s.logger.Error("list vendor targets failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the vendor's targets"})
		return
	}
	defer rows.Close()
	targets := []VendorTarget{}
	for rows.Next() {
		var t VendorTarget
		if err := rows.Scan(&t.ID, &t.TargetType, &t.TargetID, &t.TargetName, &t.CreatedAt); err != nil {
			s.logger.Error("scan vendor target failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the vendor's targets"})
			return
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("list vendor targets failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list the vendor's targets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"targets": targets})
}

// handleAddVendorTarget — POST /vendor-orgs/:id/targets {target_type,
// target_id}. A PAM entry or an application must exist in the organization;
// a network service is taken by id. Opening a target twice is a 409.
func (s *Service) handleAddVendorTarget(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if !externalid.ClosedListTargetTypes[req.TargetType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_type must be pam_entry, application or network_service"})
		return
	}
	if _, err := uuid.Parse(req.TargetID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target_id must be an id"})
		return
	}
	if !s.vendorForTargets(c, org.ID, true) {
		return
	}
	if table := map[string]string{"pam_entry": "pam_entries", "application": "applications"}[req.TargetType]; table != "" {
		var exists bool
		if err := s.db.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM `+table+` WHERE id = $1::uuid AND org_id = $2)`, req.TargetID, org.ID).Scan(&exists); err != nil {
			s.logger.Error("check vendor target failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check the target"})
			return
		}
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "no such " + req.TargetType + " in this organization"})
			return
		}
	}
	actor := c.GetString("user_id")
	var t VendorTarget
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO vendor_org_targets (org_id, vendor_org_id, target_type, target_id, created_by)
		VALUES ($1, $2::uuid, $3, $4::uuid, NULLIF($5, '')::uuid)
		RETURNING id::text, target_type, target_id::text, created_at`,
		org.ID, c.Param("id"), req.TargetType, req.TargetID, actor).Scan(&t.ID, &t.TargetType, &t.TargetID, &t.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "this target is already open to the vendor organization"})
			return
		}
		s.logger.Error("add vendor target failed", logsafe.String("vendor_org_id", c.Param("id")), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open the target"})
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_org.target_opened", "success", actor, c.Param("id"),
		"vendor_organization", map[string]interface{}{"target_type": t.TargetType, "target_id": t.TargetID})
	c.JSON(http.StatusCreated, t)
}

// handleRemoveVendorTarget — DELETE /vendor-orgs/:id/targets/:targetId. The
// vendor's external users can no longer ask for or launch it while the
// vendor is on a closed list; what they already hold is ended by its own
// window or an administrator.
func (s *Service) handleRemoveVendorTarget(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	if !s.vendorForTargets(c, org.ID, true) {
		return
	}
	var targetType, targetID string
	err = s.db.Pool.QueryRow(ctx, `
		DELETE FROM vendor_org_targets
		 WHERE id::text = $1 AND vendor_org_id::text = $2 AND org_id = $3
		RETURNING target_type, target_id::text`, c.Param("targetId"), c.Param("id"), org.ID).Scan(&targetType, &targetID)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
		return
	}
	if err != nil {
		s.logger.Error("remove vendor target failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close the target"})
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_org.target_closed", "success", c.GetString("user_id"),
		c.Param("id"), "vendor_organization", map[string]interface{}{"target_type": targetType, "target_id": targetID})
	c.Status(http.StatusNoContent)
}
