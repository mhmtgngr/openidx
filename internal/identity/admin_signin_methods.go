// Package identity - an administrator's view of one user's sign-in methods.
//
// The lockout that motivated this: an administrator's only second factor was
// push to a phone that no longer existed, the device row stayed forever, and
// nobody could see from the console that the phone had not been heard from in
// months. The user detail page now lists every factor the user has, with when
// each push device was last seen, and lets an administrator remove a factor or
// disable a push device. Every action is admin-only, scoped to the caller's
// organization and audited.
package identity

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
)

// SignInMethods is what GET /users/:id/sign-in-methods returns.
type SignInMethods struct {
	UserID               string                `json:"user_id"`
	StaleAfterDays       int                   `json:"stale_after_days"`
	TOTP                 *SignInTOTP           `json:"totp"`
	WebAuthn             []SignInWebAuthnKey   `json:"webauthn"`
	PushDevices          []SignInPushDevice    `json:"push_devices"`
	BackupCodesRemaining int                   `json:"backup_codes_remaining"`
	Email                *SignInEmailOTP       `json:"email"`
	SMS                  *SignInSMSEnrollment  `json:"sms"`
	Summary              SignInMethodsOverview `json:"summary"`
}

// SignInMethodsOverview answers the question the lockout raised: can this
// person get in with something other than a phone nobody has seen?
type SignInMethodsOverview struct {
	// UsableFactors counts the primary factors that can be used today: TOTP,
	// each security key, email, SMS, and each push device seen within the
	// stale window.
	UsableFactors int `json:"usable_factors"`
	// OnlyStalePush is true when the user's only primary factor is push and
	// none of their phones has been seen within the window.
	OnlyStalePush bool `json:"only_stale_push"`
}

type SignInTOTP struct {
	Enabled    bool       `json:"enabled"`
	EnrolledAt *time.Time `json:"enrolled_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type SignInWebAuthnKey struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	BackupEligible bool       `json:"backup_eligible"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

// Push device statuses in SignInPushDevice.Status.
const (
	PushStatusActive      = "active"       // enabled, seen within the window
	PushStatusStale       = "stale"        // enabled, not seen within the window
	PushStatusDisabled    = "disabled"     // disabled by the sweep or an administrator
	PushStatusSwitchedOff = "switched_off" // switched off, not by the system
)

type SignInPushDevice struct {
	ID             string     `json:"id"`
	DeviceName     string     `json:"device_name"`
	Platform       string     `json:"platform"`
	DeviceModel    string     `json:"device_model,omitempty"`
	AppVersion     string     `json:"app_version,omitempty"`
	Status         string     `json:"status"`
	AgentLinked    bool       `json:"agent_linked"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	DisabledAt     *time.Time `json:"disabled_at,omitempty"`
	DisabledReason string     `json:"disabled_reason,omitempty"`
}

type SignInEmailOTP struct {
	Enabled    bool       `json:"enabled"`
	Address    string     `json:"address"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type SignInSMSEnrollment struct {
	Enabled    bool       `json:"enabled"`
	Verified   bool       `json:"verified"`
	PhoneLast4 string     `json:"phone_last4"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// pushDeviceStatus classifies a device for the console.
func pushDeviceStatus(d PushMFADevice, now time.Time, staleAfter time.Duration) string {
	switch {
	case d.Enabled && PushDeviceStale(d, now, staleAfter):
		return PushStatusStale
	case d.Enabled:
		return PushStatusActive
	case d.DisabledAt != nil:
		return PushStatusDisabled
	default:
		return PushStatusSwitchedOff
	}
}

// summarizeSignInMethods fills in m.Summary from the rest of m.
func summarizeSignInMethods(m *SignInMethods) {
	other := 0
	if m.TOTP != nil && m.TOTP.Enabled {
		other++
	}
	other += len(m.WebAuthn)
	if m.Email != nil && m.Email.Enabled {
		other++
	}
	if m.SMS != nil && m.SMS.Enabled && m.SMS.Verified {
		other++
	}
	fresh, hasPush := 0, false
	for _, d := range m.PushDevices {
		switch d.Status {
		case PushStatusActive:
			fresh++
			hasPush = true
		case PushStatusStale, PushStatusDisabled:
			hasPush = true
		}
	}
	m.Summary = SignInMethodsOverview{
		UsableFactors: other + fresh,
		OnlyStalePush: other == 0 && hasPush && fresh == 0,
	}
}

// adminTargetInOrg resolves the org and checks the target user belongs to it.
// It writes the response and returns ok=false when the request cannot go on.
func (s *Service) adminTargetInOrg(c *gin.Context) (orgctx.Org, string, bool) {
	if !identityCallerIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required for this operation"})
		return orgctx.Org{}, "", false
	}
	org, err := orgctx.From(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return orgctx.Org{}, "", false
	}
	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user id is required"})
		return orgctx.Org{}, "", false
	}
	var one int
	err = s.db.Pool.QueryRow(c.Request.Context(),
		`SELECT 1 FROM users WHERE id::text = $1 AND org_id = $2`, userID, org.ID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return orgctx.Org{}, "", false
	}
	if err != nil {
		s.logger.Error("sign-in methods: could not look the user up", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to look up the user"})
		return orgctx.Org{}, "", false
	}
	return org, userID, true
}

// GetSignInMethods lists every sign-in method userID has.
func (s *Service) GetSignInMethods(ctx context.Context, userID string, now time.Time) (*SignInMethods, error) {
	staleAfter := s.PushDeviceStaleAfter()
	m := &SignInMethods{
		UserID:         userID,
		StaleAfterDays: int(staleAfter.Hours() / 24),
		WebAuthn:       []SignInWebAuthnKey{},
		PushDevices:    []SignInPushDevice{},
	}

	if totp, err := s.GetTOTPStatus(ctx, userID); err == nil && totp != nil && totp.ID != "" {
		m.TOTP = &SignInTOTP{Enabled: totp.Enabled, EnrolledAt: totp.EnrolledAt, LastUsedAt: totp.LastUsedAt}
	}

	creds, err := s.GetWebAuthnCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, c := range creds {
		m.WebAuthn = append(m.WebAuthn, SignInWebAuthnKey{
			ID: c.ID, Name: c.Name, BackupEligible: c.BackupEligible,
			CreatedAt: c.CreatedAt, LastUsedAt: c.LastUsedAt,
		})
	}

	devices, err := s.GetPushMFADevices(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		m.PushDevices = append(m.PushDevices, SignInPushDevice{
			ID: d.ID, DeviceName: d.DeviceName, Platform: d.Platform,
			DeviceModel: d.DeviceModel, AppVersion: d.AppVersion,
			Status:      pushDeviceStatus(d, now, staleAfter),
			AgentLinked: d.AgentID != "",
			CreatedAt:   d.CreatedAt, LastUsedAt: d.LastUsedAt, LastSeenAt: d.LastSeenAt,
			DisabledAt: d.DisabledAt, DisabledReason: d.DisabledReason,
		})
	}

	if n, err := s.GetBackupCodeCount(ctx, userID); err == nil {
		m.BackupCodesRemaining = n
	} else {
		return nil, err
	}

	if e, err := s.GetEmailOTPEnrollment(ctx, userID); err == nil && e != nil {
		m.Email = &SignInEmailOTP{Enabled: e.Enabled, Address: e.EmailAddress, LastUsedAt: e.LastUsedAt}
	}
	if sms, err := s.GetSMSEnrollment(ctx, userID); err == nil && sms != nil {
		last4 := sms.PhoneNumber
		if len(last4) > 4 {
			last4 = last4[len(last4)-4:]
		}
		m.SMS = &SignInSMSEnrollment{Enabled: sms.Enabled, Verified: sms.Verified, PhoneLast4: last4, LastUsedAt: sms.LastUsedAt}
	}

	summarizeSignInMethods(m)
	return m, nil
}

// handleAdminGetSignInMethods serves GET /users/:id/sign-in-methods.
func (s *Service) handleAdminGetSignInMethods(c *gin.Context) {
	_, userID, ok := s.adminTargetInOrg(c)
	if !ok {
		return
	}
	m, err := s.GetSignInMethods(c.Request.Context(), userID, time.Now())
	if err != nil {
		s.logger.Error("could not list sign-in methods", logsafe.String("user_id", userID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list sign-in methods"})
		return
	}
	c.JSON(http.StatusOK, m)
}

// adminRemovableMethods maps a method with no per-credential id to the
// statement that removes it. Each is scoped by user and org.
var adminRemovableMethods = map[string]string{
	"totp":         `DELETE FROM mfa_totp WHERE user_id = $1 AND org_id = $2`,
	"email":        `DELETE FROM mfa_email_otp WHERE user_id = $1 AND org_id = $2`,
	"sms":          `DELETE FROM mfa_sms WHERE user_id = $1 AND org_id = $2`,
	"backup_codes": `DELETE FROM mfa_backup_codes WHERE user_id = $1 AND org_id = $2 AND NOT COALESCE(used, false)`,
}

// adminRemovableCredentials maps a method with per-credential ids to the
// statement that removes one.
var adminRemovableCredentials = map[string]string{
	"webauthn": `DELETE FROM mfa_webauthn WHERE user_id = $1 AND org_id = $2 AND id::text = $3`,
	"push":     `DELETE FROM mfa_push_devices WHERE user_id = $1 AND org_id = $2 AND id::text = $3`,
}

func (s *Service) auditAdminSignInChange(c *gin.Context, action, userID string, details map[string]interface{}) {
	s.logAuditEvent(c.Request.Context(), "identity", "mfa", action, "success",
		c.GetString("user_id"), userID, "user", details)
}

// handleAdminRemoveSignInMethod serves DELETE /users/:id/sign-in-methods/:method
// for totp, email, sms and backup_codes.
func (s *Service) handleAdminRemoveSignInMethod(c *gin.Context) {
	org, userID, ok := s.adminTargetInOrg(c)
	if !ok {
		return
	}
	method := strings.ToLower(c.Param("method"))
	stmt, known := adminRemovableMethods[method]
	if !known {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown sign-in method; one of totp, email, sms, backup_codes"})
		return
	}
	tag, err := s.db.Pool.Exec(c.Request.Context(), stmt, userID, org.ID)
	if err != nil {
		s.logger.Error("could not remove a sign-in method", zap.String("method", method), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove the sign-in method"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "the user has no such sign-in method"})
		return
	}
	s.auditAdminSignInChange(c, "mfa.admin_removed", userID, map[string]interface{}{
		"method": method, "removed": tag.RowsAffected(),
	})
	c.JSON(http.StatusOK, gin.H{"removed": tag.RowsAffected()})
}

// handleAdminRemoveSignInCredential serves
// DELETE /users/:id/sign-in-methods/:method/:credential_id for webauthn and push.
func (s *Service) handleAdminRemoveSignInCredential(c *gin.Context) {
	org, userID, ok := s.adminTargetInOrg(c)
	if !ok {
		return
	}
	method := strings.ToLower(c.Param("method"))
	stmt, known := adminRemovableCredentials[method]
	if !known {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown sign-in method; one of webauthn, push"})
		return
	}
	credentialID := c.Param("credential_id")
	tag, err := s.db.Pool.Exec(c.Request.Context(), stmt, userID, org.ID, credentialID)
	if err != nil {
		s.logger.Error("could not remove a sign-in credential", zap.String("method", method), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove the sign-in method"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "the user has no such sign-in method"})
		return
	}
	s.auditAdminSignInChange(c, "mfa.admin_removed", userID, map[string]interface{}{
		"method": method, "credential_id": credentialID,
	})
	c.JSON(http.StatusOK, gin.H{"removed": tag.RowsAffected()})
}

// handleAdminDisableSignInCredential serves
// POST /users/:id/sign-in-methods/:method/:credential_id/disable. Only push
// devices can be disabled; anything else is removed instead.
//
// A disabled device keeps its row and counts as a factor the user has, so the
// login still asks for a second factor and offers the fallbacks. Registering
// the device again enables it.
func (s *Service) handleAdminDisableSignInCredential(c *gin.Context) {
	org, userID, ok := s.adminTargetInOrg(c)
	if !ok {
		return
	}
	if strings.ToLower(c.Param("method")) != "push" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only push devices can be disabled; remove other methods instead"})
		return
	}
	deviceID := c.Param("credential_id")
	found, err := s.disablePushDeviceForUser(c.Request.Context(), org.ID, userID, deviceID)
	if err != nil {
		s.logger.Error("could not disable a push device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable the push device"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "the user has no such push device"})
		return
	}
	s.auditAdminSignInChange(c, "push_device.disabled_admin", userID, map[string]interface{}{
		"method": "push", "credential_id": deviceID,
	})
	c.JSON(http.StatusOK, gin.H{"disabled": true})
}
