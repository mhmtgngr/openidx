package oauth

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/testsupport"
)

// Before this, no oauth rows reached unified_audit_events at all: the OIDC
// enforcement point's report-mode records went to audit_events, which is
// org-scoped and whose RLS policy rejects them — on the live box that table has
// taken one row since June. With ACCESS_ASSIGNMENT_ENFORCE=false (the default)
// these records are the entire evidence base for the irreversible flag flip, so
// the property under test is that they land, in a shape identical to the
// proxy's.

// oauthUnifiedAuditDDL mirrors internal/migrations/sql_v54.go, including the
// real user_id foreign key: a record naming a user who does not exist must fail
// loudly rather than appear to land.
const oauthUnifiedAuditDDL = `
CREATE TABLE IF NOT EXISTS users (
	id UUID PRIMARY KEY, org_id UUID NOT NULL, username VARCHAR(255), email VARCHAR(255));
CREATE TABLE IF NOT EXISTS proxy_routes (id UUID PRIMARY KEY, name VARCHAR(255));
CREATE TABLE IF NOT EXISTS unified_audit_events (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	org_id UUID NOT NULL,
	source VARCHAR(50) NOT NULL,
	event_type VARCHAR(100) NOT NULL,
	route_id UUID REFERENCES proxy_routes(id) ON DELETE SET NULL,
	user_id UUID REFERENCES users(id) ON DELETE SET NULL,
	actor_ip VARCHAR(45),
	details JSONB DEFAULT '{}',
	created_at TIMESTAMPTZ DEFAULT NOW());
`

// newAssignmentAuditDB starts a throwaway Postgres, applies the table shape and
// seeds one user. It skips cleanly when no container runtime is present.
func newAssignmentAuditDB(t *testing.T) (db *database.PostgresDB, userID string, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	container := testsupport.RunOrSkip(t, req.Image, func() (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	})

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("container port: %v", err)
	}
	db, err = database.NewPostgres("postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("connect: %v", err)
	}
	cleanup = func() {
		db.Close()
		container.Terminate(ctx)
	}

	if _, err := db.Pool.Exec(ctx, oauthUnifiedAuditDDL); err != nil {
		cleanup()
		t.Fatalf("create schema: %v", err)
	}
	userID = uuid.New().String()
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO users (id, org_id, username, email) VALUES ($1, $2, 'alice', 'alice@example.com')`,
		userID, uuid.New().String()); err != nil {
		cleanup()
		t.Fatalf("seed user: %v", err)
	}
	return db, userID, cleanup
}

type oauthDecisionRow struct {
	Source    string
	EventType string
	RouteID   *string
	UserID    *string
	ActorIP   *string
	Details   map[string]interface{}
}

func fetchOAuthDecision(t *testing.T, db *database.PostgresDB, userID string) oauthDecisionRow {
	t.Helper()
	var r oauthDecisionRow
	var raw []byte
	err := db.Pool.QueryRow(context.Background(), `
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

// TestOAuthAssignmentDecisionLandsInUnifiedAudit: the report-mode record reaches
// the table that accepts writes, under source "oauth" — a source
// unified_audit_events previously had no rows for at all.
func TestOAuthAssignmentDecisionLandsInUnifiedAudit(t *testing.T) {
	db, userID, cleanup := newAssignmentAuditDB(t)
	defer cleanup()

	s := &Service{db: db, logger: zap.NewNop()}
	appID := uuid.New().String()
	s.recordAssignmentDecision(context.Background(), userID, "client-abc", appID, "203.0.113.9", false)

	got := fetchOAuthDecision(t, db, userID)

	if got.Source != appaccess.SourceOIDC {
		t.Errorf("source = %q, want %q", got.Source, appaccess.SourceOIDC)
	}
	if got.EventType != appaccess.EventTypeWouldDeny {
		t.Errorf("event_type = %q, want %q", got.EventType, appaccess.EventTypeWouldDeny)
	}
	if got.RouteID != nil {
		t.Errorf("route_id = %v, want NULL — this gate exists for applications with no published route", *got.RouteID)
	}
	if got.UserID == nil || *got.UserID != userID {
		t.Errorf("user_id column = %v, want %s", got.UserID, userID)
	}
	if got.ActorIP == nil || *got.ActorIP != "203.0.113.9" {
		t.Errorf("actor_ip = %v, want 203.0.113.9", got.ActorIP)
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
	if got.Details["client_id"] != "client-abc" {
		t.Errorf("details client_id = %v, want client-abc", got.Details["client_id"])
	}
	if got.Details["enforcement_point"] != appaccess.EnforcementPointOIDC {
		t.Errorf("details enforcement_point = %v, want oidc", got.Details["enforcement_point"])
	}
	if got.Details["reason"] != appaccess.ReasonNotAssigned {
		t.Errorf("details reason = %v, want %q", got.Details["reason"], appaccess.ReasonNotAssigned)
	}
	if got.Details["enforced"] != false {
		t.Errorf("details enforced = %v, want false", got.Details["enforced"])
	}
}

// TestOAuthAssignmentDecisionRecordsUnderEnforcement: enforcement must not be
// quieter than report mode.
func TestOAuthAssignmentDecisionRecordsUnderEnforcement(t *testing.T) {
	db, userID, cleanup := newAssignmentAuditDB(t)
	defer cleanup()

	s := &Service{db: db, logger: zap.NewNop()}
	s.recordAssignmentDecision(context.Background(), userID, "client-abc", uuid.New().String(), "203.0.113.9", true)

	got := fetchOAuthDecision(t, db, userID)
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

// TestOAuthAssignmentDecisionWarnsWhenWriteFails: a write the database refuses
// (here a user id with no users row, which the real foreign key rejects) must
// surface at WARN rather than vanish. A dropped decision record is the defect.
func TestOAuthAssignmentDecisionWarnsWhenWriteFails(t *testing.T) {
	db, _, cleanup := newAssignmentAuditDB(t)
	defer cleanup()

	core, logs := observer.New(zapcore.WarnLevel)
	s := &Service{db: db, logger: zap.New(core)}
	// A real gate decision always carries a tenant, so give it one: without an
	// org on the context the recorder legitimately warns that it filed the row
	// under the primary organization, and that is a different finding from the
	// one under test.
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: uuid.New().String()})
	s.recordAssignmentDecision(ctx, uuid.New().String(), "client-abc", uuid.New().String(), "", false)

	// Match the message rather than counting every WARN. This assertion used to
	// be `len(all) != 1`, which made the test fail the moment the recorder
	// gained a second, unrelated warning -- reporting a defect in the new
	// warning rather than in the behaviour under test.
	const want = "assignment decision not recorded: unified audit write failed"
	if n := len(logs.FilterMessage(want).All()); n != 1 {
		t.Fatalf("a rejected write must be logged at WARN as %q, got %d such entries out of %d: %+v",
			want, n, logs.Len(), logs.All())
	}
}

// TestOAuthAssignmentDecisionWarnsWithNoDB: the recorder must never panic and
// never drop silently when there is no database handle.
func TestOAuthAssignmentDecisionWarnsWithNoDB(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	s := &Service{logger: zap.New(core)} // nil db

	s.recordAssignmentDecision(context.Background(), "user-1", "client-abc", "app-1", "203.0.113.9", false)

	// Same reasoning as above: name the warning, do not count them all.
	entries := logs.FilterMessage("assignment decision not recorded: no database handle").All()
	if len(entries) != 1 {
		t.Fatalf("expected exactly one WARN for the dropped record, got %d of %d: %+v",
			len(entries), logs.Len(), logs.All())
	}
	fields := entries[0].ContextMap()
	if fields["user_id"] != "user-1" || fields["application_id"] != "app-1" {
		t.Errorf("the warning must identify the decision that was lost: %v", fields)
	}
	if fields["event_type"] != appaccess.EventTypeWouldDeny {
		t.Errorf("warning event_type = %v, want %q", fields["event_type"], appaccess.EventTypeWouldDeny)
	}
}

// TestAssignmentGateRecordsOnBothBranches is the wiring guard for this side.
// The gate's decision logic is pinned by TestAuthorizeAssignmentDecision and
// must not change; this checks only that assignmentGateAllows durably records
// the decision on BOTH branches, before the 403 is written on the enforcement
// branch. A missed recording site is silent — no error, no row — which is
// exactly how the report-only phase came to prove nothing.
func TestAssignmentGateRecordsOnBothBranches(t *testing.T) {
	src, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (s *Service) assignmentGateAllows(")
	if start < 0 {
		t.Fatal("assignmentGateAllows not found — has it been renamed?")
	}
	body = body[start:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatal("could not delimit assignmentGateAllows")
	}
	fn := body[:end]

	gateAt := strings.Index(fn, "authorizeAssignmentDecision(")
	if gateAt < 0 {
		t.Fatal("assignmentGateAllows must still evaluate authorizeAssignmentDecision")
	}
	after := fn[gateAt:]

	recAt := strings.Index(after, "s.recordAssignmentDecision(")
	if recAt < 0 {
		t.Fatal("assignmentGateAllows must durably record the gate's decision — " +
			"a report-only phase whose records go nowhere proves nothing")
	}
	if strings.Count(after, "s.recordAssignmentDecision(") != 1 {
		t.Error("expected a single recording site covering both branches; a second one risks double-counting the report")
	}
	// It must sit above the if/else, i.e. before both the enforcement audit and
	// the report-mode audit, so neither branch can escape without a record.
	denyAuditAt := strings.Index(after, `"oauth_access_denied"`)
	if denyAuditAt < 0 {
		t.Fatal("could not find the enforcement-branch audit call")
	}
	if recAt > denyAuditAt {
		t.Error("the durable record must be written on both branches, not only the report-mode one")
	}
	forbidAt := strings.Index(after, "c.JSON(403,")
	if forbidAt < 0 {
		t.Fatal("could not find the gate's 403")
	}
	if recAt > forbidAt {
		t.Error("the decision must be recorded before the 403 is written")
	}
}
