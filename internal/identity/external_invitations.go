package identity

// External (vendor) invitations and the first sign-in (third-party access
// framework §5.5).
//
// An external user exists only through an invitation. POST /invitations with
// user_type "external" names the vendor organization and optionally a
// sponsor and an account lifetime; everything the invariants require is
// checked there, against the vendor, the sponsor and the groups. The invitee
// accepts at POST /invitations/:token/accept as any invitee does, and gets an
// account that cannot sign in: account_status 'pending_mfa', users.enabled
// false. The acceptance answers with an authenticator-app secret, and the
// account becomes active only at POST /invitations/:token/mfa with a code
// from it. So no external account ever has a session without a second
// factor: not through the password login, and not through a magic link,
// a passkey login or a password reset, all of which refuse a disabled
// account already.

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

// externalInviteFields are the external half of POST /invitations.
type externalInviteFields struct {
	UserType         string     `json:"user_type"`
	VendorOrgID      string     `json:"vendor_org_id"`
	SponsorUserID    string     `json:"sponsor_user_id"`
	ExpiresInDays    int        `json:"expires_in_days"`
	AccountExpiresAt *time.Time `json:"account_expires_at"`
}

// externalInvitation is what a validated external invitation stores.
type externalInvitation struct {
	VendorOrgID      string
	SponsorUserID    string
	AccountExpiresAt time.Time
}

// inviteInputError is a malformed external invitation: a 400, not a refusal.
type inviteInputError struct{ msg string }

func (e *inviteInputError) Error() string { return e.msg }

// validateExternalInvitation checks an external invitation against the
// invariants before it is stored:
//
//   - the inviter is not an external user (I12);
//   - the vendor organization exists in this org and is active;
//   - the address is in the vendor's allowed domains, when it lists any;
//   - the sponsor (given, else the vendor's default, else the inviter) is an
//     enabled, active internal user (I1, I2);
//   - the account lifetime is in the future, at most 365 days, and within the
//     vendor's contract (I1). A lifetime the inviter did not choose (the
//     vendor's default) is cut back to the contract's end rather than refused;
//   - every role is "user" (I2) and every group is open to external users
//     (I3), so the acceptance cannot fail on the database guard.
func (s *Service) validateExternalInvitation(ctx context.Context, orgID, inviter, email string,
	roles, groups []string, f externalInviteFields, now time.Time) (*externalInvitation, error) {
	if err := externalid.CheckActor(ctx, s.db.Pool, orgID, inviter); err != nil {
		return nil, err
	}
	if strings.TrimSpace(f.VendorOrgID) == "" {
		return nil, &inviteInputError{"vendor_org_id is required for an external invitation"}
	}
	vendor, err := externalid.LoadVendor(ctx, s.db.Pool, orgID, f.VendorOrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &inviteInputError{"vendor organization not found"}
	}
	if err != nil {
		return nil, err
	}
	if vendor.Status != "active" {
		return nil, externalid.ErrVendorNotActive
	}
	if !vendor.EmailAllowed(email) {
		return nil, externalid.ErrEmailDomain
	}

	sponsor := f.SponsorUserID
	if sponsor == "" {
		sponsor = vendor.DefaultSponsorUserID
	}
	if sponsor == "" {
		sponsor = inviter
	}
	if err := externalid.CheckSponsor(ctx, s.db.Pool, orgID, sponsor); err != nil {
		return nil, err
	}

	var expires time.Time
	switch {
	case f.AccountExpiresAt != nil:
		expires = f.AccountExpiresAt.UTC()
	case f.ExpiresInDays != 0:
		if f.ExpiresInDays < 1 || f.ExpiresInDays > externalid.MaxAccountDays {
			return nil, externalid.ErrExpiryTooLong
		}
		expires = now.AddDate(0, 0, f.ExpiresInDays)
	default:
		expires = now.AddDate(0, 0, vendor.DefaultExpiryDays)
		if vendor.ContractEnd != nil {
			end := time.Date(vendor.ContractEnd.Year(), vendor.ContractEnd.Month(), vendor.ContractEnd.Day(), 23, 59, 59, 0, time.UTC)
			if expires.After(end) {
				expires = end
			}
		}
	}
	if err := externalid.ValidateExpiry(now, &expires, vendor.ContractEnd); err != nil {
		return nil, err
	}

	for _, r := range roles {
		if !externalid.RoleAllowed(externalid.TypeExternal, r) {
			return nil, externalid.ErrRoleCap
		}
	}
	if len(groups) > 0 {
		var closed int
		if err := s.db.Pool.QueryRow(ctx, `
			SELECT count(*) FROM groups WHERE org_id = $1 AND name = ANY($2) AND NOT external_allowed`,
			orgID, groups).Scan(&closed); err != nil {
			return nil, err
		}
		if closed > 0 {
			return nil, externalid.ErrGroupNotExternal
		}
	}
	return &externalInvitation{VendorOrgID: f.VendorOrgID, SponsorUserID: sponsor, AccountExpiresAt: expires}, nil
}

// writeInviteError answers a failed external invitation check.
func (s *Service) writeInviteError(c *gin.Context, err error) {
	var input *inviteInputError
	if errors.As(err, &input) {
		c.JSON(http.StatusBadRequest, gin.H{"error": input.msg})
		return
	}
	if writeExternalRefusal(c, err) {
		return
	}
	s.logger.Error("external invitation check failed", zap.Error(err))
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}

// acceptExternalInvitation finishes an accepted external invitation: the
// account in 'pending_mfa', disabled, and an authenticator-app secret for the
// invitee to enroll with. The invitation is already claimed by the caller;
// release puts it back for a retryable failure (the username is taken).
func (s *Service) acceptExternalInvitation(c *gin.Context, orgID, invID, email string, roles, groups []string,
	inv externalInvitation, username, firstName, lastName, hashedPassword string, release func()) {
	ctx := c.Request.Context()

	// What may have changed since the invitation was issued: the vendor closed
	// or suspended, the sponsor gone, the lifetime run out. Each spends the
	// invitation; a new one is the way back.
	vendor, err := externalid.LoadVendor(ctx, s.db.Pool, orgID, inv.VendorOrgID)
	if err != nil || vendor.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": externalid.ErrVendorNotActive.Error(), "code": externalid.Code(externalid.ErrVendorNotActive)})
		return
	}
	if err := externalid.CheckSponsor(ctx, s.db.Pool, orgID, inv.SponsorUserID); err != nil {
		s.writeInviteError(c, err)
		return
	}
	if !inv.AccountExpiresAt.After(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired invitation"})
		return
	}

	var userID string
	err = s.db.Pool.QueryRow(ctx, `
		INSERT INTO users (org_id, username, email, first_name, last_name, enabled, email_verified,
		                   user_type, account_status, vendor_org_id, sponsor_user_id, account_expires_at, status_changed_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), false, true,
		        'external', 'pending_mfa', $6::uuid, $7::uuid, $8, NOW())
		RETURNING id::text`,
		orgID, username, email, firstName, lastName, inv.VendorOrgID, inv.SponsorUserID, inv.AccountExpiresAt).Scan(&userID)
	if err != nil {
		release()
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "the username or email address is already in use"})
			return
		}
		s.logger.Error("failed to create the external user from an invitation", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if err := s.grantInvitedAccess(ctx, userID, orgID, hashedPassword, roles, groups); err != nil {
		s.logger.Error("an external invitation was accepted but the account could not be finished",
			logsafe.String("invitation_id", invID), zap.String("user_id", userID), zap.Error(err))
		if writeExternalRefusal(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "the account was created but its password and access could not be set; ask your sponsor for a new invitation",
			"user_id": userID,
		})
		return
	}

	enrollment, err := s.GenerateTOTPSecret(ctx, userID)
	if err != nil {
		s.logger.Error("could not generate the authenticator secret for an external invitee", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "external.accepted", "success", userID, userID, "user",
		map[string]interface{}{"invitation_id": invID, "vendor_org_id": inv.VendorOrgID, "sponsor_user_id": inv.SponsorUserID})

	c.JSON(http.StatusCreated, gin.H{
		"message": "Account created. Add the secret to an authenticator app and confirm a code to activate it.",
		"user_id": userID,
		"status":  externalid.StatusPendingMFA,
		"mfa": gin.H{
			"method":      "totp",
			"secret":      enrollment.Secret,
			"otpauth_url": enrollment.QRCodeURL,
		},
	})
}

// handleCompleteInvitationMFA — POST /invitations/:token/mfa {secret, code}.
// Public, like the acceptance: the invitation token is the credential. It
// enrolls the authenticator the acceptance handed out and activates the
// account, and only an external invitation whose account still waits for its
// second factor answers. Afterwards the invitee signs in with password and
// code like any external user.
func (s *Service) handleCompleteInvitationMFA(c *gin.Context) {
	token := c.Param("token")
	var req struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "secret and code are required"})
		return
	}
	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired invitation"})
		return
	}

	var email, sponsor string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT email, COALESCE(sponsor_user_id::text, '') FROM user_invitations
		 WHERE token = $1 AND org_id = $2 AND status = 'accepted' AND user_type = 'external' AND expires_at > NOW()`,
		token, org.ID).Scan(&email, &sponsor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired invitation"})
		return
	}
	var userID string
	err = s.db.Pool.QueryRow(ctx, `
		SELECT id::text FROM users
		 WHERE org_id = $1 AND lower(email) = lower($2) AND user_type = 'external' AND account_status = 'pending_mfa'`,
		org.ID, email).Scan(&userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired invitation"})
		return
	}

	if err := s.EnrollTOTP(ContextWithActorID(ctx, userID), userID, req.Secret, req.Code); err != nil {
		s.logAuditEvent(ctx, "identity", "external_access", "external.activation_failed", "failure", userID, userID, "user",
			map[string]interface{}{"reason": "invalid_code"})
		c.JSON(http.StatusBadRequest, gin.H{"error": "the code does not match; check the authenticator app's clock and try again"})
		return
	}
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE users SET account_status = 'active', enabled = true, status_changed_at = NOW(), updated_at = NOW()
		 WHERE id = $1::uuid AND org_id = $2 AND account_status = 'pending_mfa'`, userID, org.ID)
	if err != nil || tag.RowsAffected() == 0 {
		s.logger.Error("could not activate an external account after its second factor", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	s.logAuditEvent(ctx, "identity", "external_access", "external.activated", "success", userID, userID, "user",
		map[string]interface{}{"sponsor_user_id": sponsor, "factor": "totp"})
	c.JSON(http.StatusOK, gin.H{
		"status":  externalid.StatusActive,
		"message": "Your account is active. Sign in with your password and a code from your authenticator app.",
	})
}
