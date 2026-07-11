package admin

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestIBDRContinuousAuth_RealTables guards the audit_logs/user_devices/
// blocked_ips/user_monitoring/session_risks repoints: breach indicators must
// come from audit_events, the device-anomaly factor from known_devices, the
// breach IP block must land in ip_threat_list (the deny-list the access
// evaluator reads), enhanced monitoring must be recorded in audit_events, and
// session risk history must persist to the v77 session_risks table. Before
// the fix every one of these paths hit a nonexistent table and swallowed the
// error, so breach detection and continuous-auth risk silently under-fired.
func TestIBDRContinuousAuth_RealTables(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())

	const (
		orgA    = "00000000-0000-0000-0000-000000000010" // seeded default org
		orgB    = "00000000-0000-0000-0000-0000000000c2"
		userX   = "11111111-0000-0000-0000-0000000000e1"
		session = "22222222-0000-0000-0000-0000000000e1"
		attkIP  = "203.0.113.9"
	)

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org B (ibdr test)', 'org-b-ibdr-test')`, orgB)
	exec(`INSERT INTO users (id, username, email, org_id) VALUES ($1, 'ibdr-ux', 'ibdr-ux@test.local', $2)`, userX, orgA)

	// 11 failed logins from the attacker IP + successful logins from 4
	// distinct IPs, all inside the indicator windows, all in org A.
	for i := 0; i < 11; i++ {
		exec(`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
		      VALUES (gen_random_uuid(), 'authentication', 'security', 'login_failed', 'failure', $1, $2, $1, 'user', '{}', NOW(), $3)`,
			userX, attkIP, orgA)
	}
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"} {
		exec(`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
		      VALUES (gen_random_uuid(), 'authentication', 'security', 'login', 'success', $1, $2, $1, 'user', '{}', NOW(), $3)`,
			userX, ip, orgA)
	}

	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: orgA})
	ctxB := orgctx.With(context.Background(), orgctx.Org{ID: orgB})

	ibdr := &ibdrService{db: db, logger: zap.NewNop(), config: &IBDRConfig{}}

	t.Run("breach indicators come from audit_events, org-scoped", func(t *testing.T) {
		indicators := ibdr.collectIndicators(ctxA, userX, attkIP, "ua")
		types := map[string]int{}
		for _, ind := range indicators {
			types[ind.Type]++
		}
		if types["ip"] != 1 || types["geo_anomaly"] != 1 {
			t.Fatalf("want ip + geo_anomaly indicators, got %+v", types)
		}

		// Org B sees none of org A's events.
		if got := ibdr.collectIndicators(ctxB, userX, attkIP, "ua"); len(got) != 0 {
			t.Fatalf("cross-org: want 0 indicators, got %d", len(got))
		}
	})

	t.Run("breach IP block lands in ip_threat_list", func(t *testing.T) {
		ibdr.blockIPAddress(ctxA, attkIP)
		// Read back exactly the way the access-service context evaluator does.
		var threat string
		var isActive bool
		if err := db.Pool.QueryRow(seedCtx,
			`SELECT threat_type, is_active FROM ip_threat_list WHERE ip_address=$1`, attkIP,
		).Scan(&threat, &isActive); err != nil {
			t.Fatalf("blocked IP not present in ip_threat_list: %v", err)
		}
		if threat != "breach_response" || !isActive {
			t.Fatalf("want active breach_response entry, got threat=%q active=%v", threat, isActive)
		}
		// Idempotent on re-block.
		ibdr.blockIPAddress(ctxA, attkIP)
	})

	t.Run("enhanced monitoring is recorded in audit_events", func(t *testing.T) {
		incident := &BreachIncident{ID: "33333333-0000-0000-0000-0000000000e1", AffectedUserIDs: []string{userX}}
		actions := ibdr.executePartialQuarantine(ctxA, incident, "admin-actor")
		if len(actions) < 2 { // revoked_sessions + enhanced_monitoring_<user>
			t.Fatalf("want revoke + monitoring actions, got %v", actions)
		}
		var n int
		if err := db.Pool.QueryRow(seedCtx,
			`SELECT COUNT(*) FROM audit_events WHERE action = 'user.enhanced_monitoring' AND target_id = $1 AND org_id = $2`,
			userX, orgA).Scan(&n); err != nil || n != 1 {
			t.Fatalf("want 1 enhanced_monitoring audit event, got %d (err %v)", n, err)
		}
	})

	ca := &continuousAuthService{db: db, logger: zap.NewNop(), config: &ContinuousAuthConfig{
		RiskFactors: map[string]float64{"session_age": 1, "geo_anomaly": 1, "device_anomaly": 1, "behavioral_anomaly": 1, "velocity": 1},
	}}

	t.Run("device risk reads known_devices", func(t *testing.T) {
		authCtx := &AuthContext{UserID: userX, DeviceFingerprint: "fp-ca-1"}
		if got := ca.calculateDeviceRisk(ctxA, authCtx); got != 25 {
			t.Fatalf("unknown device: want 25, got %v", got)
		}
		exec(`INSERT INTO known_devices (user_id, fingerprint, trusted, org_id) VALUES ($1, 'fp-ca-1', true, $2)`, userX, orgA)
		if got := ca.calculateDeviceRisk(ctxA, authCtx); got != 0 {
			t.Fatalf("trusted device: want 0, got %v", got)
		}
		// Org B must not see org A's device.
		if got := ca.calculateDeviceRisk(ctxB, authCtx); got != 25 {
			t.Fatalf("cross-org device: want 25, got %v", got)
		}
	})

	t.Run("velocity risk reads audit_events", func(t *testing.T) {
		// 15 recent events already seeded (11 failed + 4 success) → still
		// below the >20 threshold; add 10 more to cross it.
		for i := 0; i < 10; i++ {
			exec(`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, actor_ip, target_id, target_type, details, created_at, org_id)
			      VALUES (gen_random_uuid(), 'access', 'api', 'resource.read', 'success', $1, '10.0.0.1', $1, 'resource', '{}', NOW(), $2)`,
				userX, orgA)
		}
		authCtx := &AuthContext{UserID: userX}
		if got := ca.calculateVelocityRisk(ctxA, authCtx); got != 15 {
			t.Fatalf("25 events in the window: want velocity 15, got %v", got)
		}
	})

	t.Run("session risk history persists to v77 tables", func(t *testing.T) {
		// Exercise the exact INSERT and previous-risk SELECT from
		// CalculateSessionRisk against the migrated schema.
		if _, err := db.Pool.Exec(ctxA, `
			INSERT INTO session_risks (session_id, overall_risk, risk_level, action_required, risk_factors, calculated_at, previous_risk, risk_delta, org_id)
			VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8)
		`, session, 42.5, "medium", "monitor", []byte("{}"), 0.0, 42.5, orgA); err != nil {
			t.Fatalf("session_risks INSERT: %v", err)
		}
		var prev float64
		if err := db.Pool.QueryRow(ctxA, `
			SELECT overall_risk FROM session_risks WHERE session_id = $1 AND org_id = $2 ORDER BY calculated_at DESC LIMIT 1
		`, session, orgA).Scan(&prev); err != nil || prev != 42.5 {
			t.Fatalf("previous-risk SELECT: want 42.5, got %v (err %v)", prev, err)
		}

		exec(`INSERT INTO risk_factors (session_id, type, severity, description, detected_at, org_id)
		      VALUES ($1, 'geo_anomaly', 0.7, 'login from new location', $2, $3)`, session, time.Now(), orgA)
		factors, err := ca.GetRiskFactors(ctxA, session)
		if err != nil {
			t.Fatalf("GetRiskFactors: %v", err)
		}
		if len(factors) != 1 || factors[0].Type != "geo_anomaly" || factors[0].Severity != 0.7 {
			t.Fatalf("want the seeded geo_anomaly factor, got %+v", factors)
		}
		// Cross-org read returns nothing.
		if got, err := ca.GetRiskFactors(ctxB, session); err != nil || len(got) != 0 {
			t.Fatalf("cross-org risk factors: want 0, got %d (err %v)", len(got), err)
		}
	})
}
