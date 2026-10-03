package identity

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/logsafe"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/externalid"
)

// suspendSponsoredExternals suspends the live external (vendor) users that
// sponsorID answers for, because sponsorID is leaving: deleted, or disabled.
//
// The framework's decision D5: a departing sponsor suspends their external
// users rather than disabling them, so a new sponsor can take them over within
// the grace period, and a suspended account cannot sign in. Each account goes
// to 'suspended' with users.enabled false in one statement (the v214 CHECK
// refuses an enabled external account that is not live), and is then severed
// (severExternal): deprovisioned exactly as an administrator's disable
// deprovisions an account -- sessions with their revocation markers, API
// keys, vault checkouts and grants, JIT elevations -- and its sessions'
// end signalled to the tenant's SSF receivers.
//
// DeleteUser calls it before removing the sponsor's row: the sponsor_user_id
// foreign key sets the column NULL on delete, which the v214 CHECK refuses
// for a live account, so a delete that skipped this would fail rather than
// leave a live external user with nobody answering for them. UpdateUser calls
// it when an administrator disables the sponsor. The other writers that
// disable accounts (directory sync, lifecycle policies, the kill switch) are
// covered by the external-account sweep.
//
// Returns the suspended user ids. Best-effort after the UPDATE, like
// deprovisionUser: a failure to revoke one class is logged, not fatal.
func (s *Service) suspendSponsoredExternals(ctx context.Context, orgID, sponsorID, reason string) ([]string, error) {
	if s.db == nil || s.db.Pool == nil {
		return nil, nil
	}
	rows, err := s.db.Pool.Query(ctx, `
		UPDATE users
		   SET account_status = 'suspended', enabled = false, status_changed_at = NOW(), updated_at = NOW()
		 WHERE sponsor_user_id = $1::uuid AND org_id = $2 AND user_type = 'external'
		   AND account_status IN ('invited', 'pending_mfa', 'active')
		RETURNING id::text`, sponsorID, orgID)
	if err != nil {
		return nil, err
	}
	var suspended []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		suspended = append(suspended, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	actor := actorIDFromContext(ctx)
	for _, id := range suspended {
		if err := s.severExternal(ctx, orgID, id, externalid.StatusSuspended); err != nil {
			s.logger.Warn("could not record the severing of a suspended external user",
				zap.String("user_id", logsafe.Clean(id)), zap.Error(err))
		}
		s.logAuditEvent(ctx, "identity", "external_access", "external.suspended", "success", actor, id, "user",
			map[string]interface{}{"sponsor_user_id": sponsorID, "reason": reason})
	}
	return suspended, nil
}

// ---- External account management (Phase 1, part three) ----
//
// The routes an administrator uses on an external (vendor) account after it
// exists. Each needs a reason, which goes to the audit trail with the change,
// and each refuses an external caller (I12): the routes sit behind the
// administrator check, which an external user can never pass, and say so again
// here so the rule does not depend on the router alone.

// ExternalUser is the API view of an external account.
type ExternalUser struct {
	ID               string     `json:"id"`
	Username         string     `json:"username"`
	Email            string     `json:"email"`
	FirstName        string     `json:"first_name"`
	LastName         string     `json:"last_name"`
	Status           string     `json:"status"`
	Enabled          bool       `json:"enabled"`
	VendorOrgID      string     `json:"vendor_org_id"`
	VendorName       string     `json:"vendor_name"`
	SponsorUserID    *string    `json:"sponsor_user_id,omitempty"`
	SponsorName      string     `json:"sponsor_name"`
	AccountExpiresAt *time.Time `json:"account_expires_at,omitempty"`
	StatusChangedAt  *time.Time `json:"status_changed_at,omitempty"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	// ExpiringSoon: active, and the account ends within externalExpiringSoon.
	ExpiringSoon bool `json:"expiring_soon"`
	// HasStrongFactor: an authenticator app, passkey or push device is
	// enrolled (decision D4).
	HasStrongFactor bool `json:"has_strong_factor"`
	// ReactivateUntil: for a suspended account, the end of the window in
	// which a new sponsor can reactivate it (decision D5).
	ReactivateUntil *time.Time `json:"reactivate_until,omitempty"`
}

// externalExpiringSoon is how close to its end an active account is listed
// as expiring soon.
const externalExpiringSoon = 14 * 24 * time.Hour

// externalReq is the body every management route takes.
type externalReq struct {
	Reason           string     `json:"reason"`
	SponsorUserID    string     `json:"sponsor_user_id"`
	AccountExpiresAt *time.Time `json:"account_expires_at"`
	ExtendDays       int        `json:"extend_days"`
}

// beginExternalChange binds the body, requires a reason and an internal
// caller, and returns what the route needs. ok false means it answered.
func (s *Service) beginExternalChange(c *gin.Context) (orgID, actor string, req externalReq, ok bool) {
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return "", "", req, false
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return "", "", req, false
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason is required"})
		return "", "", req, false
	}
	actor = c.GetString("user_id")
	if err := externalid.CheckActor(c.Request.Context(), s.db.Pool, org.ID, actor); err != nil {
		if !writeExternalRefusal(c, err) {
			s.logger.Error("could not check the caller's user type", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return "", "", req, false
	}
	return org.ID, actor, req, true
}

// loadExternalAccount reads an external account of orgID, answering 404 for
// anything else (an internal user's id included). ok false means it answered.
func (s *Service) loadExternalAccount(c *gin.Context, orgID, userID string) (externalid.Account, bool) {
	a, err := externalid.Load(c.Request.Context(), s.db.Pool, orgID, userID)
	if err == nil && a.External() {
		return a, true
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("could not load the external account", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return a, false
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "external user not found"})
	return a, false
}

// severExternal ends a departed external account's live access, the way an
// administrator's disable does, tells the tenant's SSF receivers, and records
// that it was done. status is the one the account moved to. Every path that
// ends an external account severs it here: the routes, a departing sponsor,
// a closed vendor and the sweep.
//
// What the receivers are told depends on whether the account can come back
// (§6.10 of the framework):
//   - suspended: session-revoked. A new sponsor may reactivate the account
//     within the grace period (decision D5), so its sessions end and the
//     account stays;
//   - expired or disabled: account-disabled. Neither comes back: a new
//     invitation is a new account.
//
// Best-effort, like deprovisionUser: the status is already changed when this
// runs, so a signal that cannot be written is logged and the severing goes
// on. The error is the record's: a sever that is not recorded is repeated by
// the next sweep, and its signal with it.
func (s *Service) severExternal(ctx context.Context, orgID, userID, status string) error {
	s.deprovisionUser(ctx, userID, orgID, false)
	event := ssfsignal.AccountDisabled
	if status == externalid.StatusSuspended {
		event = ssfsignal.SessionRevoked
	}
	if err := ssfsignal.Enqueue(ctx, s.db.Pool, ssfsignal.Signal{
		OrgID: orgID, EventType: event, SubjectID: userID,
		Claims: map[string]any{"reason": "external_" + status},
	}); err != nil {
		s.logger.Error("an external account was severed, but its SSF signal was not enqueued",
			zap.String("user_id", logsafe.Clean(userID)), zap.String("status", status), zap.Error(err))
	}
	_, err := s.db.Pool.Exec(ctx,
		`UPDATE users SET access_severed_at = NOW() WHERE id = $1::uuid AND org_id = $2`, userID, orgID)
	return err
}

// endExternal moves a live or suspended account to a state it cannot sign in
// from, in one statement guarded by its current state, then severs it.
func (s *Service) endExternal(c *gin.Context, to, action string) {
	orgID, actor, req, ok := s.beginExternalChange(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := c.Param("id")
	a, ok := s.loadExternalAccount(c, orgID, userID)
	if !ok {
		return
	}
	from := []string{externalid.StatusPendingMFA, externalid.StatusActive}
	if to == externalid.StatusDisabled {
		from = append(from, externalid.StatusSuspended)
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE users SET account_status = $3, enabled = false, status_changed_at = NOW(), updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND user_type = 'external' AND account_status = ANY($4)`,
		userID, orgID, to, from)
	if err != nil {
		s.logger.Error("could not change the external account's status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "the account is " + a.Status + " and cannot be " + to, "code": "external_status_conflict"})
		return
	}
	if err := s.severExternal(ctx, orgID, userID, to); err != nil {
		s.logger.Warn("could not record the severing of an external account; the sweep retries it",
			zap.String("user_id", logsafe.Clean(userID)), zap.Error(err))
	}
	s.logAuditEvent(ctx, "identity", "external_access", action, "success", actor, userID, "user",
		map[string]interface{}{"reason": req.Reason, "from": a.Status})
	c.JSON(http.StatusOK, gin.H{"id": userID, "status": to})
}

// handleSuspendExternalUser — POST /external-users/:id/suspend {reason}.
func (s *Service) handleSuspendExternalUser(c *gin.Context) {
	s.endExternal(c, externalid.StatusSuspended, "external.suspended")
}

// handleDisableExternalUser — POST /external-users/:id/disable {reason}.
// Final: a disabled external account comes back only as a new invitation.
func (s *Service) handleDisableExternalUser(c *gin.Context) {
	s.endExternal(c, externalid.StatusDisabled, "external.disabled")
}

// handleExtendExternalUser — POST /external-users/:id/extend
// {reason, account_expires_at | extend_days}. Moves the account's end, within
// a year from now and the vendor's contract (I1). It does not extend grants
// written before: those were bounded by the old date (v215) and are re-granted
// by someone who can see the new one. An end moved earlier cuts every grant
// past it, in the database (v215's external_account_end_moved). An external
// user cannot extend their own account (I12).
func (s *Service) handleExtendExternalUser(c *gin.Context) {
	orgID, actor, req, ok := s.beginExternalChange(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := c.Param("id")
	a, ok := s.loadExternalAccount(c, orgID, userID)
	if !ok {
		return
	}
	now := time.Now().UTC()
	var until time.Time
	switch {
	case req.AccountExpiresAt != nil:
		until = req.AccountExpiresAt.UTC()
	case req.ExtendDays > 0 && a.ExpiresAt != nil:
		base := *a.ExpiresAt
		if base.Before(now) {
			base = now
		}
		until = base.AddDate(0, 0, req.ExtendDays)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "give account_expires_at or extend_days"})
		return
	}
	vendor, err := externalid.LoadVendor(ctx, s.db.Pool, orgID, a.VendorOrgID)
	if err != nil {
		s.logger.Error("could not load the external account's vendor", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if vendor.Status != "active" {
		writeExternalRefusal(c, externalid.ErrVendorNotActive)
		return
	}
	if err := externalid.ValidateExpiry(now, &until, vendor.ContractEnd); err != nil {
		writeExternalRefusal(c, err)
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE users SET account_expires_at = $3, updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND user_type = 'external'
		   AND account_status IN ('pending_mfa', 'active', 'suspended')`, userID, orgID, until)
	if err != nil {
		s.logger.Error("could not extend the external account", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "the account is " + a.Status + " and cannot be extended", "code": "external_status_conflict"})
		return
	}
	details := map[string]interface{}{"reason": req.Reason, "to": until.Format(time.RFC3339)}
	if a.ExpiresAt != nil {
		details["from"] = a.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.logAuditEvent(ctx, "identity", "external_access", "external.extended", "success", actor, userID, "user", details)
	c.JSON(http.StatusOK, gin.H{"id": userID, "account_expires_at": until})
}

// handleReactivateExternalUser — POST /external-users/:id/reactivate
// {reason, sponsor_user_id}. Decision D5: a suspended account comes back only
// with a sponsor, within SponsorGraceDays of its suspension, before its end,
// and while its vendor is active. After that it is final, and the sweep
// disables it.
func (s *Service) handleReactivateExternalUser(c *gin.Context) {
	orgID, actor, req, ok := s.beginExternalChange(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := c.Param("id")
	a, ok := s.loadExternalAccount(c, orgID, userID)
	if !ok {
		return
	}
	if err := externalid.CheckSponsor(ctx, s.db.Pool, orgID, req.SponsorUserID); err != nil {
		if !writeExternalRefusal(c, err) {
			s.logger.Error("could not check the sponsor", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}
	vendor, err := externalid.LoadVendor(ctx, s.db.Pool, orgID, a.VendorOrgID)
	if err != nil || vendor.Status != "active" {
		writeExternalRefusal(c, externalid.ErrVendorNotActive)
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE users
		   SET account_status = 'active', enabled = true, sponsor_user_id = $3::uuid,
		       status_changed_at = NOW(), access_severed_at = NULL, updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND user_type = 'external' AND account_status = 'suspended'
		   AND status_changed_at > NOW() - make_interval(days => $4)
		   AND account_expires_at > NOW()`, userID, orgID, req.SponsorUserID, externalid.SponsorGraceDays)
	if err != nil {
		s.logger.Error("could not reactivate the external account", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{
			"error": "only a suspended account, within " + strconv.Itoa(externalid.SponsorGraceDays) +
				" days of its suspension and before its end, can be reactivated; this one is " + a.Status,
			"code": "external_status_conflict",
		})
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "external.reactivated", "success", actor, userID, "user",
		map[string]interface{}{"reason": req.Reason, "sponsor_user_id": req.SponsorUserID, "previous_sponsor_user_id": a.SponsorUserID})
	c.JSON(http.StatusOK, gin.H{"id": userID, "status": externalid.StatusActive, "sponsor_user_id": req.SponsorUserID})
}

// handleChangeExternalSponsor — POST /external-users/:id/sponsor
// {reason, sponsor_user_id}. Hands a live account to another sponsor before
// the present one leaves.
func (s *Service) handleChangeExternalSponsor(c *gin.Context) {
	orgID, actor, req, ok := s.beginExternalChange(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	userID := c.Param("id")
	a, ok := s.loadExternalAccount(c, orgID, userID)
	if !ok {
		return
	}
	if err := externalid.CheckSponsor(ctx, s.db.Pool, orgID, req.SponsorUserID); err != nil {
		if !writeExternalRefusal(c, err) {
			s.logger.Error("could not check the sponsor", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE users SET sponsor_user_id = $3::uuid, updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND user_type = 'external'
		   AND account_status IN ('pending_mfa', 'active')`, userID, orgID, req.SponsorUserID)
	if err != nil {
		s.logger.Error("could not change the sponsor", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "the account is " + a.Status + "; reactivate a suspended one instead", "code": "external_status_conflict"})
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "external.sponsor_changed", "success", actor, userID, "user",
		map[string]interface{}{"reason": req.Reason, "sponsor_user_id": req.SponsorUserID, "previous_sponsor_user_id": a.SponsorUserID})
	c.JSON(http.StatusOK, gin.H{"id": userID, "sponsor_user_id": req.SponsorUserID})
}

// handleListExternalUsers — GET /external-users[?vendor_org_id=&status=].
func (s *Service) handleListExternalUsers(c *gin.Context) {
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT u.id::text, u.username, u.email, COALESCE(u.first_name, ''), COALESCE(u.last_name, ''),
		       u.account_status, COALESCE(u.enabled, false), u.vendor_org_id::text, COALESCE(v.name, ''),
		       u.sponsor_user_id::text, COALESCE(NULLIF(trim(COALESCE(sp.first_name, '') || ' ' || COALESCE(sp.last_name, '')), ''), sp.username, ''),
		       u.account_expires_at, u.status_changed_at, u.last_login_at, u.created_at,
		       EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.org_id = u.org_id AND t.enabled)
		    OR EXISTS (SELECT 1 FROM mfa_webauthn w WHERE w.user_id = u.id AND w.org_id = u.org_id)
		    OR EXISTS (SELECT 1 FROM mfa_push_devices p WHERE p.user_id = u.id AND p.org_id = u.org_id AND COALESCE(p.enabled, true))
		  FROM users u
		  LEFT JOIN vendor_organizations v ON v.id = u.vendor_org_id AND v.org_id = u.org_id
		  LEFT JOIN users sp ON sp.id = u.sponsor_user_id AND sp.org_id = u.org_id
		 WHERE u.org_id = $1 AND u.user_type = 'external'
		   AND ($2 = '' OR u.vendor_org_id = NULLIF($2, '')::uuid)
		   AND ($3 = '' OR u.account_status = $3)
		 ORDER BY u.account_expires_at NULLS LAST, u.username
		 LIMIT 500`, org.ID, c.Query("vendor_org_id"), c.Query("status"))
	if err != nil {
		s.logger.Error("list external users failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list external users"})
		return
	}
	defer rows.Close()
	now := time.Now()
	out := []ExternalUser{}
	for rows.Next() {
		var u ExternalUser
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName, &u.Status, &u.Enabled,
			&u.VendorOrgID, &u.VendorName, &u.SponsorUserID, &u.SponsorName, &u.AccountExpiresAt,
			&u.StatusChangedAt, &u.LastLoginAt, &u.CreatedAt, &u.HasStrongFactor); err != nil {
			s.logger.Error("scan external user failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list external users"})
			return
		}
		if u.Status == externalid.StatusActive && u.AccountExpiresAt != nil && u.AccountExpiresAt.Sub(now) < externalExpiringSoon {
			u.ExpiringSoon = true
		}
		if u.Status == externalid.StatusSuspended && u.StatusChangedAt != nil {
			until := u.StatusChangedAt.AddDate(0, 0, externalid.SponsorGraceDays)
			u.ReactivateUntil = &until
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("list external users failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list external users"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"external_users": out})
}
