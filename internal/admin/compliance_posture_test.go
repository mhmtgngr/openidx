package admin

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestCompliancePosture_MFAAdoptionFromRealTables guards the mfa_enrollments
// repoint: /compliance-posture's MFA adoption must be derived from the real
// enrollment tables. Before the fix the query read a table no migration
// creates and its swallowed error also zeroed total_enabled, so both the MFA
// adoption rate and the password compliance rate always reported 0%.
func TestCompliancePosture_MFAAdoptionFromRealTables(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())

	// A fresh org isolates the ratio from the default org's seeded users.
	const (
		orgC = "00000000-0000-0000-0000-0000000000d3"
		u1   = "11111111-0000-0000-0000-0000000000d1" // TOTP enrolled
		u2   = "11111111-0000-0000-0000-0000000000d2" // no MFA
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org C (posture test)', 'org-c-posture-test')`, orgC)
	exec(`INSERT INTO users (id, username, email, enabled, org_id) VALUES ($1, 'posture-u1', 'posture-u1@test.local', true, $2)`, u1, orgC)
	exec(`INSERT INTO users (id, username, email, enabled, org_id) VALUES ($1, 'posture-u2', 'posture-u2@test.local', true, $2)`, u2, orgC)
	exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'sec-p1', true, $2)`, u1, orgC)

	s := &Service{db: db, logger: zap.NewNop()}
	ctxC := orgctx.With(context.Background(), orgctx.Org{ID: orgC})

	posture, err := s.GetCompliancePosture(ctxC)
	if err != nil {
		t.Fatalf("GetCompliancePosture: %v", err)
	}
	if posture.MFAAdoptionRate != 50 {
		t.Fatalf("MFA adoption: want 50%% (1 of 2 enabled users enrolled), got %v", posture.MFAAdoptionRate)
	}
	// total_enabled no longer collapses to 0, so password compliance (both
	// users have never-set passwords → compliant under the 90-day rule) is
	// computable again.
	if posture.PasswordComplianceRate != 100 {
		t.Fatalf("password compliance: want 100%%, got %v", posture.PasswordComplianceRate)
	}
}
