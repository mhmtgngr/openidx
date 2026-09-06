package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// setupComplianceSchemaDB gives the compliance tests the schema the product
// actually creates, by running the migration chain.
//
// This matters more here than anywhere else in the package: the defect these
// tests exist for is a query naming a column the schema does not have, and a
// test that CREATEs its own tables cannot see that -- it defines the columns it
// then asserts on. The sibling DB tests in this package do exactly that, which
// is part of why six of these queries survived.
//
// TWO PATHS, AND THE SECOND ONE IS WHY THIS RUNS AT ALL. The first draft took
// only OPENIDX_TEST_DATABASE_URL and skipped without it -- and ci.yml never
// sets that variable, so the suite ran NOWHERE while reporting a pass;
// scripts/check-test-reachability.sh caught it on the first push. The variable
// stays the preferred path (a developer with a spare Postgres and no Docker),
// and the container fallback is what makes CI execute this. Both paths reset
// the schema and apply the chain, so a fixture cannot diverge between them.
func setupComplianceSchemaDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	ctx := context.Background()

	db, cleanup := complianceSchemaPool(t)
	if db == nil {
		return nil, func() {}
	}
	for _, stmt := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			cleanup()
			t.Fatalf("reset test schema (%s): %v", stmt, err)
		}
	}
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		cleanup()
		t.Fatalf("migrate to latest: %v", err)
	}
	return db, cleanup
}

// complianceSchemaPool returns a database to migrate: the one named by
// OPENIDX_TEST_DATABASE_URL, or a throwaway container.
func complianceSchemaPool(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	if url := os.Getenv("OPENIDX_TEST_DATABASE_URL"); url != "" {
		db, err := database.NewPostgres(url)
		if err != nil {
			t.Skipf("OPENIDX_TEST_DATABASE_URL set but unreachable: %v", err)
			return nil, func() {}
		}
		return db, func() { db.Close() }
	}
	// setupTestDB starts postgres:16-alpine and skips when no Docker daemon is
	// reachable, which is the only condition under which this suite may skip.
	return setupTestDB(t)
}

// TestComplianceControlsAgainstTheRealSchema drives the controls that reported
// compliant because their queries could not run.
//
// Six statements across compliance.go and compliance_enhanced.go named columns
// the schema does not have, and every one of them failed silently into a zero:
//
//	access_reviews.due_date      -> end_date. Overdue reviews always 0, so the
//	                                dashboard said no review was overdue.
//	sessions.created_at          -> started_at (twice). Average session length
//	                                always 0 hours, so the "sessions too long"
//	                                control never fired.
//	audit_events.resource_type   -> target_type. The GDPR report's access-by-
//	                                data-type section was empty in every report.
//	api_keys.revoked_at          -> status. BOTH halves of the expired-key
//	                                control, so an install with expired keys
//	                                still accepted reported zero findings.
//
// A control that cannot fail is not a control, and one that reports zero
// findings reads to an auditor as evidence of compliance.
func TestComplianceControlsAgainstTheRealSchema(t *testing.T) {
	db, cleanup := setupComplianceSchemaDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())
	const (
		org  = "00000000-0000-0000-0000-000000000010"
		user = "66666666-0000-0000-0000-0000000000c1"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}

	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'comp-u', 'comp-u@test.local', $2)`, user, org)

	// An access review whose deadline passed a week ago and which is still
	// pending: the exact thing the overdue count exists to surface.
	exec(`INSERT INTO access_reviews (id, name, type, status, start_date, end_date, org_id)
	      VALUES (gen_random_uuid(), 'Q3 privileged access', 'user_access', 'pending',
	              NOW() - INTERVAL '30 days', NOW() - INTERVAL '7 days', $1)`, org)

	// An API key that expired yesterday and was never revoked.
	exec(`INSERT INTO api_keys (id, name, key_prefix, key_hash, user_id, status, expires_at, org_id)
	      VALUES (gen_random_uuid(), 'stale integration', 'oidx_aaa', 'hash-expired', $1, 'active',
	              NOW() - INTERVAL '1 day', $2)`, user, org)
	// And one that is live. "Active" here means status='active' AND not past
	// its expiry, so the expired key above is not counted twice.
	exec(`INSERT INTO api_keys (id, name, key_prefix, key_hash, user_id, status, expires_at, org_id)
	      VALUES (gen_random_uuid(), 'live integration', 'oidx_bbb', 'hash-live', $1, 'active',
	              NOW() + INTERVAL '30 days', $2)`, user, org)

	// A session that ran for four hours.
	exec(`INSERT INTO sessions (id, user_id, client_id, org_id, started_at, expires_at)
	      VALUES (gen_random_uuid(), $1, 'console', $2, NOW() - INTERVAL '1 hour', NOW() + INTERVAL '3 hours')`,
		user, org)

	// A data-access event of a known target type.
	exec(`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, target_id, target_type, details, timestamp, created_at, org_id)
	      VALUES (gen_random_uuid(), 'data_access', 'data', 'record.read', 'success', $1, $1, 'user_record', '{}', NOW(), NOW(), $2)`,
		user, org)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	svc := &Service{db: db, logger: zap.NewNop()}
	from, to := time.Now().Add(-24*time.Hour), time.Now().Add(time.Hour)

	t.Run("an overdue access review is counted", func(t *testing.T) {
		m := svc.getAccessReviewMetrics(ctx, from, to)
		if m.OverdueReviews != 1 {
			t.Errorf("OverdueReviews = %d, want 1 -- a review a week past its end_date "+
				"and still pending", m.OverdueReviews)
		}
	})

	t.Run("session length is measured", func(t *testing.T) {
		m := svc.getSessionManagementMetrics(ctx)
		if m.ActiveSessions != 1 {
			t.Errorf("ActiveSessions = %d, want 1", m.ActiveSessions)
		}
		if m.AverageSessionHours <= 0 {
			t.Errorf("AverageSessionHours = %v, want the seeded four-hour session",
				m.AverageSessionHours)
		}
	})

	t.Run("data access is grouped by the type of thing accessed", func(t *testing.T) {
		m := svc.getDataAccessMetrics(ctx, from, to)
		if got := m.AccessByDataType["user_record"]; got != 1 {
			t.Errorf("AccessByDataType[user_record] = %d, want 1; got map %v",
				got, m.AccessByDataType)
		}
	})

	t.Run("an expired unrevoked API key is a finding", func(t *testing.T) {
		a := svc.evaluateCC6LogicalAccess(ctx, from, to)
		var found bool
		for _, f := range a.Findings {
			if contains(f, "expired API keys have not been revoked") {
				found = true
			}
		}
		if !found {
			t.Errorf("CC6 reported no expired-key finding against an install with one; findings: %v",
				a.Findings)
		}
		// The evidence line carries both counts, and both were 0 before.
		var evidenced bool
		for _, e := range a.Evidence {
			if contains(e, "Active API keys: 1, Expired but not revoked: 1") {
				evidenced = true
			}
		}
		if !evidenced {
			t.Errorf("CC6 evidence does not carry the measured key counts: %v", a.Evidence)
		}
	})
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
