package identity

// Vendor organizations: the suppliers whose people are the organization's
// external users (migration v214, third-party access framework §5.1).
//
// A vendor organization lives inside the tenant, under the same FORCE RLS
// belt as every org-scoped table, and every statement here also names org_id.
// It is created and edited by an administrator (the identity route group
// already requires one, and an external user can never hold that role). It is
// never deleted: closing it is the end of the relationship, disables every
// external user it holds and cannot be undone, so the audit trail keeps
// pointing at a record that still exists.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/externalid"
)

// VendorOrganization is the API view of a vendor_organizations row.
type VendorOrganization struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Status               string     `json:"status"`
	ContactName          string     `json:"contact_name"`
	ContactEmail         string     `json:"contact_email"`
	ContractStart        *string    `json:"contract_start"`
	ContractEnd          *string    `json:"contract_end"`
	AllowedEmailDomains  []string   `json:"allowed_email_domains"`
	DefaultExpiryDays    int        `json:"default_expiry_days"`
	DefaultSponsorUserID string     `json:"default_sponsor_user_id"`
	Notes                string     `json:"notes"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	ClosedAt             *time.Time `json:"closed_at,omitempty"`
	// ClosedList is invariant I11: the vendor's external users ask for and
	// launch only the targets opened to the vendor (/vendor-orgs/:id/targets).
	ClosedList bool `json:"closed_list"`
	// ExternalUsers counts the vendor's external users by account status.
	ExternalUsers map[string]int `json:"external_users"`
}

// vendorOrgReq is the create/update body. Dates are YYYY-MM-DD.
type vendorOrgReq struct {
	Name                 string   `json:"name"`
	Status               string   `json:"status"`
	ContactName          string   `json:"contact_name"`
	ContactEmail         string   `json:"contact_email"`
	ContractStart        string   `json:"contract_start"`
	ContractEnd          string   `json:"contract_end"`
	AllowedEmailDomains  []string `json:"allowed_email_domains"`
	DefaultExpiryDays    int      `json:"default_expiry_days"`
	DefaultSponsorUserID string   `json:"default_sponsor_user_id"`
	Notes                string   `json:"notes"`
	// ClosedList, when given, sets the closed list (I11); left out, an update
	// keeps what the vendor has and a create starts with it off.
	ClosedList *bool `json:"closed_list"`
}

var errVendorOrgNotFound = errors.New("vendor organization not found")

const vendorOrgDateLayout = "2006-01-02"

// normalize validates the body and fills defaults. Status may be active or
// suspended here; closed is reachable only through the close route.
func (r *vendorOrgReq) normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return errors.New("name is required")
	}
	if r.Status == "" {
		r.Status = "active"
	}
	if r.Status != "active" && r.Status != "suspended" {
		return errors.New("status must be active or suspended; close a vendor organization with POST /vendor-orgs/:id/close")
	}
	if r.DefaultExpiryDays == 0 {
		r.DefaultExpiryDays = externalid.DefaultAccountDays
	}
	if r.DefaultExpiryDays < 1 || r.DefaultExpiryDays > externalid.MaxAccountDays {
		return errors.New("default_expiry_days must be between 1 and 365")
	}
	var start, end time.Time
	var err error
	if r.ContractStart != "" {
		if start, err = time.Parse(vendorOrgDateLayout, r.ContractStart); err != nil {
			return errors.New("contract_start must be a date (YYYY-MM-DD)")
		}
	}
	if r.ContractEnd != "" {
		if end, err = time.Parse(vendorOrgDateLayout, r.ContractEnd); err != nil {
			return errors.New("contract_end must be a date (YYYY-MM-DD)")
		}
	}
	if !start.IsZero() && !end.IsZero() && start.After(end) {
		return errors.New("contract_start must not be after contract_end")
	}
	domains := make([]string, 0, len(r.AllowedEmailDomains))
	seen := map[string]bool{}
	for _, d := range r.AllowedEmailDomains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "@")))
		if d == "" || seen[d] {
			continue
		}
		if strings.ContainsAny(d, " @/") || !strings.Contains(d, ".") {
			return errors.New("allowed_email_domains must be domain names such as supplier.example")
		}
		seen[d] = true
		domains = append(domains, d)
	}
	r.AllowedEmailDomains = domains
	return nil
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// vendorOrgSelect projects a vendor organization with its external-user counts.
const vendorOrgSelect = `
	SELECT v.id::text, v.name, v.status, COALESCE(v.contact_name, ''), COALESCE(v.contact_email, ''),
	       to_char(v.contract_start, 'YYYY-MM-DD'), to_char(v.contract_end, 'YYYY-MM-DD'),
	       v.allowed_email_domains, v.default_expiry_days, COALESCE(v.default_sponsor_user_id::text, ''),
	       COALESCE(v.notes, ''), v.created_at, v.updated_at, v.closed_at, v.closed_list,
	       COALESCE((SELECT jsonb_object_agg(s.account_status, s.n) FROM (
	           SELECT u.account_status, count(*) AS n FROM users u
	            WHERE u.vendor_org_id = v.id AND u.org_id = v.org_id GROUP BY u.account_status) s), '{}'::jsonb)
	  FROM vendor_organizations v`

func scanVendorOrg(row pgx.Row) (*VendorOrganization, error) {
	var v VendorOrganization
	if err := row.Scan(&v.ID, &v.Name, &v.Status, &v.ContactName, &v.ContactEmail,
		&v.ContractStart, &v.ContractEnd, &v.AllowedEmailDomains, &v.DefaultExpiryDays,
		&v.DefaultSponsorUserID, &v.Notes, &v.CreatedAt, &v.UpdatedAt, &v.ClosedAt, &v.ClosedList, &v.ExternalUsers); err != nil {
		return nil, err
	}
	if v.AllowedEmailDomains == nil {
		v.AllowedEmailDomains = []string{}
	}
	return &v, nil
}

// GetVendorOrganization reads one vendor organization of the caller's org.
func (s *Service) GetVendorOrganization(ctx context.Context, id string) (*VendorOrganization, error) {
	org, err := orgctx.From(ctx)
	if err != nil {
		return nil, err
	}
	v, err := scanVendorOrg(s.db.Pool.QueryRow(ctx, vendorOrgSelect+` WHERE v.id = $1::uuid AND v.org_id = $2`, id, org.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errVendorOrgNotFound
	}
	return v, err
}

func (s *Service) handleListVendorOrgs(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, vendorOrgSelect+` WHERE v.org_id = $1 ORDER BY lower(v.name)`, org.ID)
	if err != nil {
		s.logger.Error("list vendor organizations failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list vendor organizations"})
		return
	}
	defer rows.Close()
	out := []VendorOrganization{}
	for rows.Next() {
		v, err := scanVendorOrg(rows)
		if err != nil {
			s.logger.Error("scan vendor organization failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list vendor organizations"})
			return
		}
		out = append(out, *v)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("list vendor organizations failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list vendor organizations"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"vendor_organizations": out})
}

func (s *Service) handleGetVendorOrg(c *gin.Context) {
	v, err := s.GetVendorOrganization(c.Request.Context(), c.Param("id"))
	if errors.Is(err, errVendorOrgNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		s.logger.Error("get vendor organization failed", logsafe.String("id", c.Param("id")), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load vendor organization"})
		return
	}
	c.JSON(http.StatusOK, v)
}

// checkDefaultSponsor validates an optional default sponsor.
func (s *Service) checkDefaultSponsor(ctx context.Context, orgID, sponsorID string) error {
	if sponsorID == "" {
		return nil
	}
	return externalid.CheckSponsor(ctx, s.db.Pool, orgID, sponsorID)
}

func (s *Service) handleCreateVendorOrg(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	var req vendorOrgReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := req.normalize(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.checkDefaultSponsor(ctx, org.ID, req.DefaultSponsorUserID); err != nil {
		if writeExternalRefusal(c, err) {
			return
		}
		s.logger.Error("check default sponsor failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check the default sponsor"})
		return
	}
	actor := c.GetString("user_id")
	var id string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO vendor_organizations
		    (org_id, name, status, contact_name, contact_email, contract_start, contract_end,
		     allowed_email_domains, default_expiry_days, default_sponsor_user_id, notes, created_by, closed_list)
		VALUES ($1, $2, $3, $4, $5, $6::date, $7::date, $8, $9, $10::uuid, $11, NULLIF($12, '')::uuid, COALESCE($13::boolean, false))
		RETURNING id::text`,
		org.ID, req.Name, req.Status, nullIfEmpty(req.ContactName), nullIfEmpty(req.ContactEmail),
		nullIfEmpty(req.ContractStart), nullIfEmpty(req.ContractEnd), req.AllowedEmailDomains,
		req.DefaultExpiryDays, nullIfEmpty(req.DefaultSponsorUserID), nullIfEmpty(req.Notes), actor, req.ClosedList).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "a vendor organization with this name already exists"})
			return
		}
		s.logger.Error("create vendor organization failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create vendor organization"})
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_org.created", "success", actor, id, "vendor_organization",
		map[string]interface{}{"name": req.Name, "default_expiry_days": req.DefaultExpiryDays, "closed_list": req.ClosedList != nil && *req.ClosedList})
	v, err := s.GetVendorOrganization(ctx, id)
	if err != nil {
		c.JSON(http.StatusCreated, gin.H{"id": id})
		return
	}
	c.JSON(http.StatusCreated, v)
}

func (s *Service) handleUpdateVendorOrg(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	var req vendorOrgReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := req.normalize(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.checkDefaultSponsor(ctx, org.ID, req.DefaultSponsorUserID); err != nil {
		if writeExternalRefusal(c, err) {
			return
		}
		s.logger.Error("check default sponsor failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check the default sponsor"})
		return
	}
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		s.logger.Error("update vendor organization: begin failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The status before the update, locked, so the accounts follow the
	// transition this update makes and no other.
	var prevStatus string
	err = tx.QueryRow(ctx, `SELECT status FROM vendor_organizations WHERE id = $1::uuid AND org_id = $2 FOR UPDATE`,
		id, org.ID).Scan(&prevStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": errVendorOrgNotFound.Error()})
		return
	}
	if err != nil {
		s.logger.Error("update vendor organization: read failed", logsafe.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
		return
	}
	// A closed vendor stays closed: the update names status <> 'closed'.
	tag, err := tx.Exec(ctx, `
		UPDATE vendor_organizations
		   SET name = $3, status = $4, contact_name = $5, contact_email = $6,
		       contract_start = $7::date, contract_end = $8::date, allowed_email_domains = $9,
		       default_expiry_days = $10, default_sponsor_user_id = $11::uuid, notes = $12,
		       closed_list = COALESCE($13::boolean, closed_list), updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND status <> 'closed'`,
		id, org.ID, req.Name, req.Status, nullIfEmpty(req.ContactName), nullIfEmpty(req.ContactEmail),
		nullIfEmpty(req.ContractStart), nullIfEmpty(req.ContractEnd), req.AllowedEmailDomains,
		req.DefaultExpiryDays, nullIfEmpty(req.DefaultSponsorUserID), nullIfEmpty(req.Notes), req.ClosedList)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "a vendor organization with this name already exists"})
			return
		}
		s.logger.Error("update vendor organization failed", logsafe.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "a closed vendor organization cannot be changed", "code": "vendor_org_closed"})
		return
	}
	// The vendor's accounts follow its status. Suspending it suspends each
	// live account (invited, pending_mfa, active), to be severed after the
	// commit. A suspension, not a disable: the accounts come back when the
	// vendor does, through the reactivation a departed sponsor's accounts
	// take. Reactivating it restarts the reactivation window of its suspended
	// accounts (restartVendorGrace). Any other transition moves no account.
	var suspended []string
	var restarted int64
	switch {
	case prevStatus != "suspended" && req.Status == "suspended":
		rows, err := tx.Query(ctx, `
			UPDATE users SET account_status = 'suspended', enabled = false, status_changed_at = NOW(), updated_at = NOW()
			 WHERE vendor_org_id = $1::uuid AND org_id = $2 AND user_type = 'external'
			   AND account_status IN ('invited', 'pending_mfa', 'active')
			RETURNING id::text`, id, org.ID)
		if err != nil {
			s.logger.Error("suspend vendor organization: suspend users failed", logsafe.String("id", id), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
			return
		}
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err != nil {
				rows.Close()
				s.logger.Error("suspend vendor organization: scan failed", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
				return
			}
			suspended = append(suspended, uid)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			s.logger.Error("suspend vendor organization: suspend users failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
			return
		}
	case prevStatus == "suspended" && req.Status == "active":
		if restarted, err = restartVendorGrace(ctx, tx, org.ID, id); err != nil {
			s.logger.Error("reactivate vendor organization: restarting its accounts' window failed", logsafe.String("id", id), zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Error("update vendor organization: commit failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vendor organization"})
		return
	}
	// After the commit, as the close does: a revocation for a suspension a
	// rolled-back update would not have made is a lie the other way.
	actor := c.GetString("user_id")
	for _, uid := range suspended {
		if err := s.severExternal(ctx, org.ID, uid, externalid.StatusSuspended); err != nil {
			s.logger.Warn("suspend vendor organization: could not record the severing", zap.Error(err))
		}
		s.logAuditEvent(ctx, "identity", "external_access", "external.suspended", "success", actor, uid, "user",
			map[string]interface{}{"vendor_org_id": id, "reason": "vendor organization suspended"})
	}
	updated := map[string]interface{}{"name": req.Name, "status": req.Status}
	if prevStatus != req.Status {
		updated["previous_status"] = prevStatus
		updated["users_suspended"] = len(suspended)
		updated["users_grace_restarted"] = restarted
	}
	if req.ClosedList != nil {
		updated["closed_list"] = *req.ClosedList
	}
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_org.updated", "success", actor, id,
		"vendor_organization", updated)
	v, err := s.GetVendorOrganization(ctx, id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"id": id})
		return
	}
	c.JSON(http.StatusOK, v)
}

// restartVendorGrace restarts the reactivation window
// (externalid.SponsorGraceDays, decision D5) of a reactivated vendor's
// suspended accounts, inside the update's transaction. The sweep does not run
// that window down while the vendor is suspended, and the reactivation route
// refuses an account whose vendor is not active, so without the restart an
// account held longer than the window would be disabled by the sweep the
// minute its vendor came back. Nothing is reactivated here: each account
// still needs a sponsor to take it back.
func restartVendorGrace(ctx context.Context, tx pgx.Tx, orgID, vendorID string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE users SET status_changed_at = NOW(), updated_at = NOW()
		 WHERE vendor_org_id = $1::uuid AND org_id = $2 AND user_type = 'external'
		   AND account_status = 'suspended'`, vendorID, orgID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// handleCloseVendorOrg — POST /vendor-orgs/:id/close {reason}. Closes the
// vendor organization and disables every external user it holds: each
// account goes to 'disabled' with users.enabled false, and is deprovisioned
// (sessions, API keys, vault checkouts and grants, JIT elevations), the same
// severing an administrator's disable runs. Irreversible: a closed vendor
// cannot be reopened, and its people need new invitations under a new vendor
// record.
func (s *Service) handleCloseVendorOrg(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	id := c.Param("id")
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&req)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason is required"})
		return
	}

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		s.logger.Error("close vendor organization: begin failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close vendor organization"})
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE vendor_organizations SET status = 'closed', closed_at = NOW(), updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND status <> 'closed'`, id, org.ID)
	if err != nil {
		s.logger.Error("close vendor organization failed", logsafe.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close vendor organization"})
		return
	}
	if tag.RowsAffected() == 0 {
		if v, gerr := s.GetVendorOrganization(ctx, id); gerr == nil && v.Status == "closed" {
			c.JSON(http.StatusConflict, gin.H{"error": "the vendor organization is already closed", "code": "vendor_org_closed"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": errVendorOrgNotFound.Error()})
		return
	}
	rows, err := tx.Query(ctx, `
		UPDATE users SET account_status = 'disabled', enabled = false, status_changed_at = NOW(), updated_at = NOW()
		 WHERE vendor_org_id = $1::uuid AND org_id = $2 AND user_type = 'external'
		   AND account_status NOT IN ('expired', 'disabled')
		RETURNING id::text`, id, org.ID)
	if err != nil {
		s.logger.Error("close vendor organization: disable users failed", logsafe.String("id", id), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close vendor organization"})
		return
	}
	var disabled []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			s.logger.Error("close vendor organization: scan failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close vendor organization"})
			return
		}
		disabled = append(disabled, uid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Error("close vendor organization: disable users failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close vendor organization"})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Error("close vendor organization: commit failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close vendor organization"})
		return
	}

	// After the commit, never inside it: a revocation marker for access a
	// rolled-back close would have left in place is a lie the other way.
	for _, uid := range disabled {
		if err := s.severExternal(ctx, org.ID, uid, externalid.StatusDisabled); err != nil {
			s.logger.Warn("close vendor organization: could not record the severing", zap.Error(err))
		}
	}
	actor := c.GetString("user_id")
	s.logAuditEvent(ctx, "identity", "external_access", "vendor_org.closed", "success", actor, id, "vendor_organization",
		map[string]interface{}{"reason": req.Reason, "users_disabled": len(disabled)})
	for _, uid := range disabled {
		s.logAuditEvent(ctx, "identity", "external_access", "external.disabled", "success", actor, uid, "user",
			map[string]interface{}{"vendor_org_id": id, "reason": "vendor organization closed"})
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "status": "closed", "users_disabled": len(disabled)})
}
