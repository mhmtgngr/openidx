package admin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Tenant isolation for the breach response surface, migration v147.
//
// breach_incidents and breach_alerts are the IBDR record: what was detected,
// which users and sessions it affected, what containment was applied. Before
// v147 neither carried an org_id and internal/admin/ibdr.go read both
// install-wide — the console's incident list had no predicate at all.
//
// The case worth naming is not a disclosure. TriggerIncidentResponse took a
// BARE incident id, while the actions it invokes were ALREADY org-scoped. So an
// administrator of one tenant triggering response on another tenant's incident
// disabled nobody and revoked nothing — and still flipped that tenant's
// incident to 'investigating' and recorded containment steps against it.
// Scoping the action without scoping the record it acts on turns a cross-tenant
// write into a silent no-op instead of a refusal, and leaves the owning
// tenant's real incident marked as handled. That is worse than either half
// alone, which is why the last case here asserts a REFUSAL and an untouched
// incident, not merely that org B's quarantine matched nothing.
//
// The harness connects as the container superuser, which bypasses RLS, so what
// these prove is the explicit org predicate in every query. The FORCE RLS belt
// is proven separately by test/integration/cross_org_test.go under a
// NOSUPERUSER NOBYPASSRLS role.

type breachFixture struct {
	t          *testing.T
	db         *database.PostgresDB
	s          *Service
	ibdr       *ibdrService
	orgA, orgB string
}

func newBreachFixture(t *testing.T) (*breachFixture, func()) {
	t.Helper()
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return nil, func() {}
	}
	f := &breachFixture{
		t:    t,
		db:   db,
		s:    &Service{db: db, logger: zap.NewNop()},
		ibdr: &ibdrService{db: db, logger: zap.NewNop(), config: &IBDRConfig{AutoQuarantineThreshold: 0.7}},
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	f.orgA = f.seedOrg("br-a-" + suffix)
	f.orgB = f.seedOrg("br-b-" + suffix)
	return f, cleanup
}

func (f *breachFixture) bypass() context.Context { return orgctx.WithBypassRLS(context.Background()) }

func (f *breachFixture) exec(q string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.bypass(), q, args...); err != nil {
		f.t.Fatalf("exec (%s): %v", q, err)
	}
}

func (f *breachFixture) seedOrg(slug string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.bypass(),
		"INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id", slug).Scan(&id); err != nil {
		f.t.Fatalf("seed org %s: %v", slug, err)
	}
	return id
}

func (f *breachFixture) seedUser(org, name string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.bypass(), `
		INSERT INTO users (username, email, enabled, org_id)
		VALUES ($1::varchar, $1::varchar || '@br.test', true, $2::uuid) RETURNING id`, name, org).Scan(&id); err != nil {
		f.t.Fatalf("seed user %s: %v", name, err)
	}
	return id
}

// seedIncident writes an incident directly, the way a detection in that tenant
// would have left it: status 'detected', no containment steps yet.
func (f *breachFixture) seedIncident(org, title, severity, userID string) string {
	f.t.Helper()
	var id string
	if err := f.db.Pool.QueryRow(f.bypass(), `
		INSERT INTO breach_incidents (type, severity, status, title, description, affected_user_ids,
			affected_sessions, detection_method, first_detected_at, last_activity_at, confidence,
			quarantine_action, org_id)
		VALUES ('credential_stuffing', $1, 'detected', $2, 'seeded', ARRAY[$3]::text[],
			ARRAY[]::text[], 'test', NOW(), NOW(), 0.9, 'none', $4)
		RETURNING id`, severity, title, userID, org).Scan(&id); err != nil {
		f.t.Fatalf("seed incident %s: %v", title, err)
	}
	return id
}

func (f *breachFixture) ctx(org string) context.Context {
	return orgctx.With(context.Background(), orgctx.Org{ID: org})
}

// call invokes a gin handler as an admin of org.
func (f *breachFixture) call(org string, h gin.HandlerFunc, method, path string) *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, bytes.NewReader(nil)).WithContext(f.ctx(org))
	c.Set("roles", []string{"admin"})
	c.Set("user_id", "00000000-0000-0000-0000-000000000001")
	h(c)
	return w
}

func TestTenantIsolation_BreachResponse(t *testing.T) {
	f, cleanup := newBreachFixture(t)
	if f == nil {
		return
	}
	defer cleanup()

	userA := f.seedUser(f.orgA, "br-user-a-"+f.orgA[:8])
	userB := f.seedUser(f.orgB, "br-user-b-"+f.orgB[:8])

	incidentA := f.seedIncident(f.orgA, "org A incident", "critical", userA)
	incidentB := f.seedIncident(f.orgB, "org B incident", "critical", userB)

	f.exec(`INSERT INTO breach_alerts (incident_id, type, severity, message, user_id, ip_address, org_id)
		VALUES ($1, 'credential_stuffing', 'critical', 'org A alert', $2, '203.0.113.7', $3)`,
		incidentA, userA, f.orgA)
	f.exec(`INSERT INTO breach_alerts (incident_id, type, severity, message, user_id, ip_address, org_id)
		VALUES ($1, 'credential_stuffing', 'critical', 'org B alert', $2, '198.51.100.7', $3)`,
		incidentB, userB, f.orgB)

	t.Run("the console's incident list is per org", func(t *testing.T) {
		// handleIBDRIncidents was `SELECT ... FROM breach_incidents ORDER BY
		// first_detected_at DESC LIMIT 100` — no predicate at all, so every
		// tenant's incident titles, descriptions and quarantine actions were on
		// every tenant's admin's screen.
		w := f.call(f.orgB, f.s.handleIBDRIncidents, "GET", "/api/v1/ibdr/incidents")
		if w.Code != http.StatusOK {
			t.Fatalf("list: %d %s", w.Code, w.Body.String())
		}
		var got struct {
			Data []BreachIncident `json:"data"`
		}
		decode(t, w, &got)
		for _, inc := range got.Data {
			if inc.ID == incidentA {
				t.Fatalf("org B's incident list contains org A's incident %q", inc.Title)
			}
		}
		if len(got.Data) != 1 || got.Data[0].ID != incidentB {
			t.Fatalf("org B should see exactly its own incident, got %d rows", len(got.Data))
		}
	})

	t.Run("alerts are per org, and every alert scans", func(t *testing.T) {
		// `WHERE acknowledged = $1 OR $1 = true` is a filter, not a tenant
		// filter, and each row names a user, a session and an IP address.
		//
		// Both seeded alerts leave session_id NULL — which is what createAlert
		// writes for any incident with no affected session, i.e. every incident
		// the detector had no session id for. That NULL used to fail the scan
		// into a string; the error was discarded, the zero value appended, and
		// pgx closed the rows, so the list stopped at the first such alert. The
		// assertions below therefore check the CONTENT of what comes back, not
		// just the row count: against the unscoped code the count alone was
		// accidentally right, for the wrong reason.
		alerts, err := f.ibdr.GetBreachAlerts(f.ctx(f.orgB), true)
		if err != nil {
			t.Fatalf("GetBreachAlerts: %v", err)
		}
		for _, a := range alerts {
			if a.IncidentID == incidentA {
				t.Fatalf("org B received org A's alert (%s, ip %s)", a.Message, a.IPAddress)
			}
		}
		if len(alerts) != 1 {
			t.Fatalf("org B should see exactly its own alert, got %d", len(alerts))
		}
		if alerts[0].IncidentID != incidentB || alerts[0].Message != "org B alert" || alerts[0].IPAddress != "198.51.100.7" {
			t.Fatalf("org B's alert came back blank: %+v. A NULL session_id fails the scan, and the "+
				"loop discarded that error and appended the zero value", alerts[0])
		}
	})

	t.Run("pattern analysis counts only this tenant", func(t *testing.T) {
		out, err := f.ibdr.AnalyzeBreachPatterns(f.ctx(f.orgB), 24*time.Hour)
		if err != nil {
			t.Fatalf("AnalyzeBreachPatterns: %v", err)
		}
		bySeverity, _ := out["by_severity"].(map[BreachSeverity]int)
		if got := bySeverity[BreachSeverityCritical]; got != 1 {
			t.Fatalf("org B's critical count = %d, want 1 (its own incident only); the aggregate "+
				"used to run over the whole install", got)
		}
	})

	t.Run("detection refuses a user from another organization", func(t *testing.T) {
		// An incident raised in org B against org A's user could never be
		// contained: executeFullQuarantine and revokeUserSessions both write
		// `... AND org_id = $2`, so the quarantine would match zero rows and
		// report success.
		if _, err := f.ibdr.DetectBreachAttempt(f.ctx(f.orgB), userA, "203.0.113.9", "ua", ""); err == nil {
			t.Fatal("org B raised a breach incident against org A's user; the containment that " +
				"follows is org-scoped and would have quarantined nobody")
		}
	})

	// THE POINT OF THIS FILE.
	t.Run("response on another tenant's incident is refused, not silently no-opped", func(t *testing.T) {
		err := f.ibdr.TriggerIncidentResponse(f.ctx(f.orgB), incidentA, "org-b-admin", false)
		if err == nil {
			t.Fatal("org B triggered incident response on org A's incident and it succeeded")
		}

		// A refusal is not enough on its own: the old code's damage was what it
		// left behind on the owning tenant's row.
		var status, quarantine, steps string
		if qerr := f.db.Pool.QueryRow(f.bypass(), `
			SELECT status, quarantine_action, COALESCE(containment_steps::text, '')
			FROM breach_incidents WHERE id = $1`, incidentA).Scan(&status, &quarantine, &steps); qerr != nil {
			t.Fatalf("read back org A's incident: %v", qerr)
		}
		if status != string(StatusDetected) {
			t.Fatalf("org A's incident is now %q. Org B's trigger flipped it to 'investigating' "+
				"while quarantining nobody — the owning tenant's real incident reads as handled", status)
		}
		if quarantine != "none" || steps != "" {
			t.Fatalf("org A's incident records containment (%q, steps=%q) that org B's trigger never "+
				"performed", quarantine, steps)
		}

		// And org A's user is untouched.
		var enabled bool
		if qerr := f.db.Pool.QueryRow(f.bypass(),
			`SELECT enabled FROM users WHERE id = $1`, userA).Scan(&enabled); qerr != nil {
			t.Fatalf("read back org A's user: %v", qerr)
		}
		if !enabled {
			t.Fatal("org B's trigger disabled org A's user")
		}
	})

	t.Run("response in the owning tenant actually contains", func(t *testing.T) {
		// The other half of the same assertion: the fix must not turn the
		// containment into a refusal for everybody.
		//
		// This also pins the quarantine itself. executeFullQuarantine wrote
		// `UPDATE users SET status = 'quarantined'` — there is no status column
		// on users, no migration creates one, and every other disable path in
		// the product writes `enabled = false`. The UPDATE errored on every
		// call, `_, _ =` discarded the error, and `disabled_user_<id>` was
		// appended regardless. A critical-severity full quarantine reported
		// disabling users it had not disabled, in its OWN tenant.
		f.exec(`INSERT INTO sessions (user_id, client_id, expires_at, org_id)
			VALUES ($1, 'br-test', NOW() + INTERVAL '1 hour', $2)`, userA, f.orgA)

		if err := f.ibdr.TriggerIncidentResponse(f.ctx(f.orgA), incidentA, "org-a-admin", false); err != nil {
			t.Fatalf("org A's own incident response failed: %v", err)
		}

		var enabled bool
		if err := f.db.Pool.QueryRow(f.bypass(),
			`SELECT enabled FROM users WHERE id = $1`, userA).Scan(&enabled); err != nil {
			t.Fatalf("read back user: %v", err)
		}
		if enabled {
			t.Fatal("a critical-severity full quarantine left the affected user enabled")
		}

		var revoked int
		if err := f.db.Pool.QueryRow(f.bypass(),
			`SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND revoked`, userA).Scan(&revoked); err != nil {
			t.Fatalf("read back sessions: %v", err)
		}
		if revoked != 1 {
			t.Fatalf("full quarantine revoked %d of org A's sessions, want 1", revoked)
		}

		var status, quarantine, steps string
		if err := f.db.Pool.QueryRow(f.bypass(), `
			SELECT status, quarantine_action, COALESCE(containment_steps::text, '')
			FROM breach_incidents WHERE id = $1`, incidentA).Scan(&status, &quarantine, &steps); err != nil {
			t.Fatalf("read back incident: %v", err)
		}
		if status != string(StatusInvestigating) || quarantine != "full" {
			t.Fatalf("after org A's own response the incident is status=%q quarantine=%q, want "+
				"investigating/full", status, quarantine)
		}
		// The third silent failure in this function: the UPDATE that records the
		// containment writes a containment_steps column no migration in
		// internal/migrations ever created (only the legacy standalone tree
		// declares it), and `_, _ =` discarded the error — so quarantine_action
		// never landed either, and the console's incident list read 'none' for
		// incidents that had been fully quarantined. v147 adds the column.
		if !strings.Contains(steps, "disabled_user_"+userA) || !strings.Contains(steps, "revoked_all_sessions") {
			t.Fatalf("the containment record is %q; want the steps that actually ran "+
				"(disabled_user_%s, revoked_all_sessions)", steps, userA)
		}
	})
}
