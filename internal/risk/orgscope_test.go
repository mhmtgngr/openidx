package risk

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// v1.7.0 org-scoping contract: risk-service methods that touch a tenant-scoped
// table (known_devices, login_history, security_alerts, stepup_challenges,
// audit_events, sessions, mfa_totp, users) read the org from context and refuse
// to run without one. The guard fires before any DB access, so these hold with a
// nil pool. Risk evaluation and the admin alert views run behind the resolver, so
// the request always carries an org; the only deliberately cross-org paths are the
// background alert-retention sweep (CleanupOldAlerts) and the alert-delivery
// goroutine (storeAlert), both marked / handled with //orgscope:ignore.
func TestRisk_requireOrgContext(t *testing.T) {
	s := &Service{}
	ctx := context.Background()

	t.Run("RegisterDevice", func(t *testing.T) {
		_, _, err := s.RegisterDevice(ctx, "u-1", "fp", "1.2.3.4", "ua", "loc")
		assertNoOrg(t, err)
	})
	t.Run("GetUserDevices", func(t *testing.T) {
		_, err := s.GetUserDevices(ctx, "u-1")
		assertNoOrg(t, err)
	})
	t.Run("GetAllDevices", func(t *testing.T) {
		_, _, err := s.GetAllDevices(ctx, 10, 0)
		assertNoOrg(t, err)
	})
	t.Run("TrustDevice", func(t *testing.T) {
		assertNoOrg(t, s.TrustDevice(ctx, "d-1"))
	})
	t.Run("RevokeDevice", func(t *testing.T) {
		assertNoOrg(t, s.RevokeDevice(ctx, "d-1"))
	})
	t.Run("GetLoginHistory", func(t *testing.T) {
		_, err := s.GetLoginHistory(ctx, "u-1", 10)
		assertNoOrg(t, err)
	})
	t.Run("GetRiskStats", func(t *testing.T) {
		_, err := s.GetRiskStats(ctx)
		assertNoOrg(t, err)
	})
	t.Run("CreateStepUpChallenge", func(t *testing.T) {
		_, err := s.CreateStepUpChallenge(ctx, "u-1", "sess-1", "reason")
		assertNoOrg(t, err)
	})
	t.Run("CompleteStepUpChallenge", func(t *testing.T) {
		assertNoOrg(t, s.CompleteStepUpChallenge(ctx, "c-1", "u-1"))
	})
	t.Run("UpdateUserRiskBaseline", func(t *testing.T) {
		assertNoOrg(t, s.UpdateUserRiskBaseline(ctx, "u-1"))
	})
	t.Run("CalculateEnhancedRiskScore", func(t *testing.T) {
		_, err := s.CalculateEnhancedRiskScore(ctx, "u-1", "1.2.3.4", "US", "ua", 10)
		assertNoOrg(t, err)
	})
	t.Run("DetectCredentialStuffing", func(t *testing.T) {
		_, err := s.DetectCredentialStuffing(ctx, "1.2.3.4", 10*time.Minute)
		assertNoOrg(t, err)
	})
	t.Run("GetUserLoginPatterns", func(t *testing.T) {
		_, err := s.GetUserLoginPatterns(ctx, "u-1")
		assertNoOrg(t, err)
	})
	t.Run("GetRiskTimeline", func(t *testing.T) {
		_, err := s.GetRiskTimeline(ctx, 30)
		assertNoOrg(t, err)
	})
	t.Run("CreateSecurityAlert", func(t *testing.T) {
		assertNoOrg(t, s.CreateSecurityAlert(ctx, &SecurityAlert{}))
	})
	t.Run("ListSecurityAlerts", func(t *testing.T) {
		_, _, err := s.ListSecurityAlerts(ctx, "", "", "", 10, 0)
		assertNoOrg(t, err)
	})
	t.Run("GetSecurityAlert", func(t *testing.T) {
		_, err := s.GetSecurityAlert(ctx, "a-1")
		assertNoOrg(t, err)
	})
	t.Run("UpdateAlertStatus", func(t *testing.T) {
		assertNoOrg(t, s.UpdateAlertStatus(ctx, "a-1", "resolved", "admin"))
	})
	t.Run("RemediateAccountLock", func(t *testing.T) {
		assertNoOrg(t, s.RemediateAccountLock(ctx, "u-1"))
	})
	t.Run("RemediateRevokeSessions", func(t *testing.T) {
		assertNoOrg(t, s.RemediateRevokeSessions(ctx, "u-1"))
	})
	t.Run("RemediateRequireReauth", func(t *testing.T) {
		assertNoOrg(t, s.RemediateRequireReauth(ctx, "u-1"))
	})
}

func TestRisk_AlertManager_requireOrgContext(t *testing.T) {
	a := &AlertManager{}
	ctx := context.Background()

	t.Run("GetAlert", func(t *testing.T) {
		_, err := a.GetAlert(ctx, "a-1")
		assertNoOrg(t, err)
	})
	t.Run("AcknowledgeAlert", func(t *testing.T) {
		assertNoOrg(t, a.AcknowledgeAlert(ctx, "a-1", "admin"))
	})
	t.Run("ResolveAlert", func(t *testing.T) {
		assertNoOrg(t, a.ResolveAlert(ctx, "a-1", "admin"))
	})
	t.Run("MarkAsFalsePositive", func(t *testing.T) {
		assertNoOrg(t, a.MarkAsFalsePositive(ctx, "a-1", "admin"))
	})
}

func assertNoOrg(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, orgctx.ErrNoOrgContext) {
		t.Fatalf("err = %v, want orgctx.ErrNoOrgContext", err)
	}
}
