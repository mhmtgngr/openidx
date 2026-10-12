package identity

// One-click vendor suspension: POST /vendor-orgs/:id/suspend {reason}. The
// same transition PUT /vendor-orgs/:id makes with status "suspended", for the
// moment someone needs a vendor cut off now and should not have to fill in the
// vendor form to do it: every live account of the vendor is suspended and
// severed (sessions and tokens revoked, PAM grants, leases and sessions ended,
// the overlay identity removed by the access service's deprovision sweep), and
// every started engagement of the vendor gives up its grants before the
// response, rather than at the sweep's next tick. A reason is required and
// audited. Reactivating the vendor is the vendor form's status, as before;
// each account then waits for its sponsor to take it back.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

func (s *Service) handleSuspendVendorOrg(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Reason == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a reason is required to suspend a vendor organization"})
		return
	}
	id := c.Param("id")
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": errVendorOrgNotFound.Error()})
		return
	}
	fail := func(what string, err error) {
		s.logger.Error("suspend vendor organization failed", zap.String("step", what), logsafe.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to suspend the vendor organization"})
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		fail("begin", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM vendor_organizations WHERE id = $1::uuid AND org_id = $2 FOR UPDATE`,
		id, org.ID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": errVendorOrgNotFound.Error()})
		return
	}
	if err != nil {
		fail("read", err)
		return
	}
	if status != "active" {
		c.JSON(http.StatusConflict, gin.H{"error": "only an active vendor organization can be suspended", "code": "vendor_org_" + status})
		return
	}
	if _, err := tx.Exec(ctx, `UPDATE vendor_organizations SET status = 'suspended', updated_at = NOW() WHERE id = $1::uuid AND org_id = $2`,
		id, org.ID); err != nil {
		fail("update", err)
		return
	}
	rows, err := tx.Query(ctx, `
		UPDATE users SET account_status = 'suspended', enabled = false, status_changed_at = NOW(), updated_at = NOW()
		 WHERE vendor_org_id = $1::uuid AND org_id = $2 AND user_type = 'external'
		   AND account_status IN ('invited', 'pending_mfa', 'active')
		RETURNING id::text`, id, org.ID)
	if err != nil {
		fail("suspend users", err)
		return
	}
	var suspended []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			fail("scan", err)
			return
		}
		suspended = append(suspended, uid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		fail("suspend users", err)
		return
	}
	// The members are no longer active, so each started engagement's sync
	// now wants nothing and cuts what it wrote.
	var cut engagementSync
	erows, err := tx.Query(ctx, `
		SELECT id::text FROM vendor_engagements
		 WHERE vendor_org_id = $1::uuid AND org_id = $2 AND status = 'open' AND starts_at <= NOW()`, id, org.ID)
	if err != nil {
		fail("list engagements", err)
		return
	}
	var engagements []string
	for erows.Next() {
		var eid string
		if err := erows.Scan(&eid); err != nil {
			erows.Close()
			fail("scan", err)
			return
		}
		engagements = append(engagements, eid)
	}
	erows.Close()
	for _, eid := range engagements {
		sy, err := syncEngagementGrants(ctx, tx, org.ID, eid)
		if err != nil {
			fail("cut engagement grants", err)
			return
		}
		cut.PamCut += sy.PamCut
		cut.AppsCut += sy.AppsCut
	}
	if err := tx.Commit(ctx); err != nil {
		fail("commit", err)
		return
	}
	actor := c.GetString("user_id")
	for _, uid := range suspended {
		if err := s.severExternal(ctx, org.ID, uid, externalid.StatusSuspended); err != nil {
			s.logger.Warn("suspend vendor organization: could not record the severing", zap.Error(err))
		}
		s.logAuditEvent(ctx, "identity", "external_access", "external.suspended", "success", actor, uid, "user",
			map[string]interface{}{"vendor_org_id": id, "reason": "vendor organization suspended: " + body.Reason})
	}
	summary := map[string]interface{}{
		"reason": body.Reason, "users_suspended": len(suspended), "engagements": len(engagements),
		"pam_grants_cut": cut.PamCut, "app_assignments_cut": cut.AppsCut,
	}
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_org.suspended", "success", actor, id, "vendor_organization", summary)
	v, err := s.GetVendorOrganization(ctx, id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"id": id, "summary": summary})
		return
	}
	c.JSON(http.StatusOK, gin.H{"vendor_organization": v, "summary": summary})
}
