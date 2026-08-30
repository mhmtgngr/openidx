package access

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/internal/appaccess"
)

// The proxy enforcement point's report-mode records used to go to audit_events
// via the audit-service POST. On the live box that table has taken ONE row
// since June (the org-scoped RLS policy rejects those writes) while
// unified_audit_events, right beside it, holds half a million rows and takes
// writes today. With ACCESS_ASSIGNMENT_ENFORCE=false — the DEFAULT — those
// records are the entire evidence base for deciding whether flipping the flag
// is safe, and the flip is irreversible. So "the record landed" is the property
// under test here, against a real table with the real foreign keys, not a
// mock.

// unifiedAuditDDL is the v54 shape of the table (internal/migrations/sql_v54.go),
// with the two real foreign keys: a record naming a route or user that does not
// exist must fail loudly rather than appear to land.
const unifiedAuditDDL = `
CREATE TABLE IF NOT EXISTS orgs (id UUID PRIMARY KEY);
CREATE TABLE IF NOT EXISTS users (
	id UUID PRIMARY KEY, org_id UUID NOT NULL, username VARCHAR(255),
	email VARCHAR(255));
CREATE TABLE IF NOT EXISTS proxy_routes (
	id UUID PRIMARY KEY, name VARCHAR(255));
CREATE TABLE IF NOT EXISTS unified_audit_events (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	source VARCHAR(50) NOT NULL,
	event_type VARCHAR(100) NOT NULL,
	route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
	user_id UUID REFERENCES users(id) ON DELETE SET NULL,
	actor_ip VARCHAR(45),
	details JSONB DEFAULT '{}',
	created_at TIMESTAMPTZ DEFAULT NOW());
`

type recordedDecision struct {
	Source    string
	EventType string
	RouteID   *string
	UserID    *string
	ActorIP   *string
	Details   map[string]interface{}
}

// fetchDecision reads back the single decision record for a user.
func fetchDecision(t *testing.T, s *Service, userID string) recordedDecision {
	t.Helper()
	var r recordedDecision
	var raw []byte
	err := s.db.Pool.QueryRow(context.Background(), `
		SELECT source, event_type, route_id, user_id, actor_ip, details
		  FROM unified_audit_events WHERE user_id = $1`, userID).
		Scan(&r.Source, &r.EventType, &r.RouteID, &r.UserID, &r.ActorIP, &raw)
	if err != nil {
		t.Fatalf("no decision record landed for user %s: %v", userID, err)
	}
	if err := json.Unmarshal(raw, &r.Details); err != nil {
		t.Fatalf("details not valid JSON: %v", err)
	}
	return r
}

// newDecisionAuditFixture spins up a container, creates the real table shape,
// and returns a Service wired the way production wires it (auditService set
// post-construction via SetAuditService) plus the seeded user and route ids.
func newDecisionAuditFixture(t *testing.T) (s *Service, userID, routeID string, cleanup func()) {
	t.Helper()
	db, dbCleanup := setupTestDB(t) // skips cleanly when no container runtime is present
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, unifiedAuditDDL); err != nil {
		dbCleanup()
		t.Fatalf("create schema: %v", err)
	}

	orgID := uuid.New().String()
	userID = uuid.New().String()
	routeID = uuid.New().String()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO orgs (id) VALUES ($1)`, orgID); err != nil {
		dbCleanup()
		t.Fatalf("seed org: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, org_id, username, email) VALUES ($1, $2, 'alice', 'alice@example.com')`,
		userID, orgID); err != nil {
		dbCleanup()
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_routes (id, name) VALUES ($1, 'app.example.com')`, routeID); err != nil {
		dbCleanup()
		t.Fatalf("seed route: %v", err)
	}

	s = &Service{db: db, logger: zap.NewNop()}
	s.SetAuditService(NewUnifiedAuditService(db, zap.NewNop()))
	return s, userID, routeID, dbCleanup
}

// TestAssignmentDecisionLandsInUnifiedAudit: the report-mode record reaches the
// table that accepts writes, with the source, event type, user, route and
// details an operator's go/no-go query reads.
func TestAssignmentDecisionLandsInUnifiedAudit(t *testing.T) {
	s, userID, routeID, cleanup := newDecisionAuditFixture(t)
	defer cleanup()

	appID := uuid.New().String()
	route := &ProxyRoute{ID: routeID, Name: "app.example.com"}
	s.recordAssignmentDecision(context.Background(), route, userID, appID, "203.0.113.7", false)

	got := fetchDecision(t, s, userID)

	if got.Source != appaccess.SourceProxy {
		t.Errorf("source = %q, want %q", got.Source, appaccess.SourceProxy)
	}
	if got.EventType != appaccess.EventTypeWouldDeny {
		t.Errorf("event_type = %q, want %q", got.EventType, appaccess.EventTypeWouldDeny)
	}
	if got.RouteID == nil || *got.RouteID != routeID {
		t.Errorf("route_id = %v, want %s", got.RouteID, routeID)
	}
	if got.UserID == nil || *got.UserID != userID {
		t.Errorf("user_id column = %v, want %s", got.UserID, userID)
	}
	if got.ActorIP == nil || *got.ActorIP != "203.0.113.7" {
		t.Errorf("actor_ip = %v, want 203.0.113.7", got.ActorIP)
	}

	for _, k := range appaccess.DecisionDetailKeys {
		if _, ok := got.Details[k]; !ok {
			t.Errorf("details missing canonical key %q: %v", k, got.Details)
		}
	}
	if got.Details["user_id"] != userID {
		t.Errorf("details user_id = %v, want %s", got.Details["user_id"], userID)
	}
	if got.Details["application_id"] != appID {
		t.Errorf("details application_id = %v, want %s", got.Details["application_id"], appID)
	}
	if got.Details["enforcement_point"] != appaccess.EnforcementPointProxy {
		t.Errorf("details enforcement_point = %v, want proxy", got.Details["enforcement_point"])
	}
	if got.Details["reason"] != appaccess.ReasonNotAssigned {
		t.Errorf("details reason = %v, want %q", got.Details["reason"], appaccess.ReasonNotAssigned)
	}
	if got.Details["enforced"] != false {
		t.Errorf("details enforced = %v, want false", got.Details["enforced"])
	}
	if got.Details["route"] != "app.example.com" {
		t.Errorf("details route = %v, want app.example.com", got.Details["route"])
	}
}

// TestAssignmentDecisionRecordsUnderEnforcement: enforcement must not be
// quieter than report mode. An actual denial records too, distinguishable by
// event_type but carrying the identical canonical keys.
func TestAssignmentDecisionRecordsUnderEnforcement(t *testing.T) {
	s, userID, routeID, cleanup := newDecisionAuditFixture(t)
	defer cleanup()

	appID := uuid.New().String()
	route := &ProxyRoute{ID: routeID, Name: "app.example.com"}
	s.recordAssignmentDecision(context.Background(), route, userID, appID, "203.0.113.7", true)

	got := fetchDecision(t, s, userID)

	if got.EventType != appaccess.EventTypeDenied {
		t.Errorf("event_type = %q, want %q", got.EventType, appaccess.EventTypeDenied)
	}
	if got.Details["enforced"] != true {
		t.Errorf("details enforced = %v, want true", got.Details["enforced"])
	}
	for _, k := range appaccess.DecisionDetailKeys {
		if _, ok := got.Details[k]; !ok {
			t.Errorf("details missing canonical key %q under enforcement: %v", k, got.Details)
		}
	}
}

// TestAssignmentDecisionWarnsWhenAuditServiceNil: auditService is set
// post-construction (SetAuditService), so it can be nil. A nil service must not
// panic, must not change the verdict, and must NOT swallow the record silently
// — a dropped decision record is the exact defect this work fixes, so it has to
// be visible at WARN.
func TestAssignmentDecisionWarnsWhenAuditServiceNil(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	s := &Service{logger: zap.New(core)} // no db, no auditService

	s.recordAssignmentDecision(context.Background(),
		&ProxyRoute{ID: "route-1", Name: "app.example.com"},
		"user-1", "app-1", "203.0.113.7", false)

	entries := logs.FilterLevelExact(zapcore.WarnLevel).All()
	if len(entries) != 1 {
		t.Fatalf("expected exactly one WARN for the dropped record, got %d: %+v", len(entries), entries)
	}
	fields := entries[0].ContextMap()
	if fields["user_id"] != "user-1" || fields["application_id"] != "app-1" {
		t.Errorf("the warning must identify the decision that was lost: %v", fields)
	}
	if fields["event_type"] != appaccess.EventTypeWouldDeny {
		t.Errorf("warning event_type = %v, want %q", fields["event_type"], appaccess.EventTypeWouldDeny)
	}

	// A nil route must be tolerated too, and the enforcement case must warn
	// just as loudly.
	s.recordAssignmentDecision(context.Background(), nil, "user-2", "app-2", "", true)
	if n := len(logs.FilterLevelExact(zapcore.WarnLevel).All()); n != 2 {
		t.Errorf("expected a second WARN (nil route, enforced), got %d total", n)
	}
}

// TestAssignmentDecisionWarnsWhenWriteFails: a write that the database refuses
// (here: a user id with no users row, which the real foreign key rejects) must
// also surface at WARN rather than vanish.
func TestAssignmentDecisionWarnsWhenWriteFails(t *testing.T) {
	s, _, routeID, cleanup := newDecisionAuditFixture(t)
	defer cleanup()

	core, logs := observer.New(zapcore.WarnLevel)
	s.logger = zap.New(core)

	ghost := uuid.New().String() // no users row → FK violation
	s.recordAssignmentDecision(context.Background(),
		&ProxyRoute{ID: routeID, Name: "app.example.com"},
		ghost, uuid.New().String(), "203.0.113.7", false)

	if n := len(logs.FilterLevelExact(zapcore.WarnLevel).All()); n != 1 {
		t.Fatalf("a rejected write must be logged at WARN, got %d entries", n)
	}
}

// readSource returns the body of the named function from a source file in this
// package (or a sibling package directory), delimited the way the oauth
// package's mint-site guards delimit theirs.
func readSource(t *testing.T, path, funcSig string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	body := string(src)
	start := strings.Index(body, funcSig)
	if start < 0 {
		t.Fatalf("%q not found in %s — has it been renamed or moved?", funcSig, path)
	}
	body = body[start:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatalf("could not delimit function starting %q in %s", funcSig, path)
	}
	return body[:end]
}

// TestProxyGateRecordsOnBothBranches is the wiring guard. The decision logic
// itself is pinned by TestProxyAssignmentDecision and must not change; what
// this checks is that handleProxy's gate calls the durable recorder on BOTH the
// report-mode branch and the enforcement branch, so enforcement cannot end up
// quieter than report mode. A missed call site is silent — no error, no row —
// which is exactly how the previous version of this record failed.
func TestProxyGateRecordsOnBothBranches(t *testing.T) {
	src := readSource(t, "service.go", "func (s *Service) handleProxy(")

	gateAt := strings.Index(src, "proxyAssignmentDecision(appID,")
	if gateAt < 0 {
		t.Fatal("handleProxy must still evaluate the gate via proxyAssignmentDecision")
	}
	after := src[gateAt:]

	recAt := strings.Index(after, "s.recordAssignmentDecision(")
	if recAt < 0 {
		t.Fatal("handleProxy must durably record the gate's decision after evaluating it — " +
			"a report-only phase whose records go nowhere proves nothing")
	}
	if strings.Count(after, "s.recordAssignmentDecision(") != 1 {
		t.Error("expected a single recording site covering both branches; a second one risks double-counting the report")
	}
	if !strings.Contains(after, "!allow || freshAssignment") {
		t.Error("the recorder must fire on an actual denial (!allow) as well as on a fresh report-mode gap — " +
			"enforcement must not be quieter than report mode")
	}
	// The record must be written before the 403, so a denied request cannot
	// leave without evidence.
	denyAt := strings.Index(after, `gin.H{"error": "not assigned to this application"}`)
	if denyAt < 0 {
		t.Fatal("could not find the assignment 403 in handleProxy")
	}
	if recAt > denyAt {
		t.Error("the decision must be recorded before the 403 is written")
	}
}

// TestBothEnforcementPointsUseTheSharedShape is the cross-package anti-drift
// guard. A reviewer previously found the two points emitting different outcome
// strings, with the user id in the actor field on one side and buried in
// details on the other — so no single query found both. The shape now lives in
// internal/appaccess; this asserts neither side hand-rolls its own map or
// event-type literal again.
func TestBothEnforcementPointsUseTheSharedShape(t *testing.T) {
	sites := []struct{ name, path string }{
		{"proxy", "service.go"},
		{"oidc", filepath.Join("..", "oauth", "assignment_audit.go")},
	}
	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			src := readSource(t, site.path, "func (s *Service) recordAssignmentDecision(")
			for _, want := range []string{"appaccess.DecisionEventType(", "appaccess.DecisionDetails("} {
				if !strings.Contains(src, want) {
					t.Errorf("%s recorder must build its record with %s so the two points cannot drift apart", site.name, want)
				}
			}
			for _, literal := range []string{`"access.assignment.would_deny"`, `"access.assignment.denied"`} {
				if strings.Contains(src, literal) {
					t.Errorf("%s recorder hard-codes %s instead of using appaccess.DecisionEventType", site.name, literal)
				}
			}
			// Both must target unified_audit_events. audit_events is the
			// org-scoped table whose RLS policy is where these records went to
			// die (one row since June, on the live box).
			if strings.Contains(src, "INSERT INTO audit_events") {
				t.Errorf("%s recorder must not target audit_events", site.name)
			}
			// A record that cannot be written must be logged, never dropped.
			if !strings.Contains(src, "s.logger.Warn(") {
				t.Errorf("%s recorder must log at warn when a record cannot be written — "+
					"a silently dropped decision record is the defect being fixed", site.name)
			}
		})
	}
}
