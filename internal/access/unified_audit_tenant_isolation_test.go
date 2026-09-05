package access

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The console's Unified Audit page is fed by QueryEvents, which opened
// `WHERE 1=1` until v142. On a multi-tenant install that meant every admin saw
// every tenant's audit trail: the enforcement decisions taken on other
// tenants' applications, their users' actor IPs, and — through the users JOIN
// the query performs to render a friendly name — their users' e-mail
// addresses. The summary endpoint counted the same way, so the "last 24 hours"
// headline on one tenant's page was the sum of everybody's activity.
//
// These tests are the ones that would have caught it. They deliberately do not
// rely on RLS: the fixture creates a plain table with no policy, so what is
// being asserted is that the QUERY names the tenant. The belt is proved
// separately, against a real NOSUPERUSER role, by TestRLSBeltTables in
// test/integration. Both matter — a query that leans entirely on RLS is one
// `WithBypassRLS` away from leaking again.
const unifiedAuditIsolationSchema = `
CREATE TABLE IF NOT EXISTS organizations (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	name VARCHAR(255) NOT NULL,
	created_at TIMESTAMPTZ DEFAULT NOW());
CREATE TABLE IF NOT EXISTS users (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	org_id UUID,
	email VARCHAR(255));
CREATE TABLE IF NOT EXISTS proxy_routes (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	org_id UUID,
	name VARCHAR(255));
CREATE TABLE IF NOT EXISTS unified_audit_events (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	org_id UUID NOT NULL,
	source VARCHAR(50) NOT NULL,
	event_type VARCHAR(100) NOT NULL,
	route_id UUID,
	user_id UUID,
	actor_ip VARCHAR(45),
	details JSONB DEFAULT '{}',
	created_at TIMESTAMPTZ DEFAULT NOW());
`

const (
	uaOrgA = "00000000-0000-0000-0000-0000000000a1"
	uaOrgB = "00000000-0000-0000-0000-0000000000b1"
)

func newUnifiedAuditService(t *testing.T) (*UnifiedAuditService, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.Skip("no database available")
	}
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, unifiedAuditIsolationSchema); err != nil {
		cleanup()
		t.Fatalf("apply schema: %v", err)
	}
	for _, org := range []string{uaOrgA, uaOrgB} {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO organizations (id, name) VALUES ($1,$2)`, org, "org-"+org[len(org)-2:]); err != nil {
			cleanup()
			t.Fatalf("seed org %s: %v", org, err)
		}
	}
	return NewUnifiedAuditService(db, zap.NewNop()), ctx, cleanup
}

// TestQueryEventsIsScopedToOneTenant is the regression test for the leak
// itself: org B's rows must not appear in org A's answer, however many of them
// there are and whatever filters org A passes.
func TestQueryEventsIsScopedToOneTenant(t *testing.T) {
	uas, ctx, cleanup := newUnifiedAuditService(t)
	defer cleanup()

	seed := []struct{ org, source, eventType string }{
		{uaOrgA, "oauth", "access.assignment.would_deny"},
		{uaOrgA, "oauth", "access.assignment.denied"},
		{uaOrgB, "oauth", "access.assignment.denied"},
		{uaOrgB, "guacamole", "connection.start"},
		{uaOrgB, "mcp", "mcp.tool.allowed"},
	}
	for _, s := range seed {
		if _, err := uas.db.Pool.Exec(ctx,
			`INSERT INTO unified_audit_events (org_id, source, event_type) VALUES ($1,$2,$3)`,
			s.org, s.source, s.eventType); err != nil {
			t.Fatalf("seed %v: %v", s, err)
		}
	}

	aCtx := orgctx.With(ctx, orgctx.Org{ID: uaOrgA})
	res, err := uas.QueryEvents(aCtx, &AuditQueryFilters{Limit: 50})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if res.Total != 2 {
		t.Errorf("Total = %d, want 2 (org A's rows only)", res.Total)
	}
	if len(res.Events) != 2 {
		t.Errorf("got %d events, want 2", len(res.Events))
	}

	// The source list drives the page's filter chips. Unscoped, it told org A
	// that somebody on this install runs Guacamole and an MCP gateway.
	for _, src := range res.Sources {
		if src != "oauth" {
			t.Errorf("org A sees source %q, which only org B produces", src)
		}
	}

	// A filter must narrow within the tenant, never widen past it: asking for
	// org B's source by name still returns nothing.
	res, err = uas.QueryEvents(aCtx, &AuditQueryFilters{Sources: []string{"guacamole"}, Limit: 50})
	if err != nil {
		t.Fatalf("QueryEvents(filtered): %v", err)
	}
	if res.Total != 0 || len(res.Events) != 0 {
		t.Errorf("filtering for another tenant's source returned %d rows; want 0", len(res.Events))
	}
}

// TestQueryEventsRefusesWithoutOrgContext: no org on the context is a
// programmer error (the resolver middleware did not run), and the honest
// answer is an error rather than every tenant's audit trail.
func TestQueryEventsRefusesWithoutOrgContext(t *testing.T) {
	uas, ctx, cleanup := newUnifiedAuditService(t)
	defer cleanup()

	if _, err := uas.db.Pool.Exec(ctx,
		`INSERT INTO unified_audit_events (org_id, source, event_type) VALUES ($1,'oauth','probe')`,
		uaOrgA); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := uas.QueryEvents(ctx, &AuditQueryFilters{Limit: 50}); err == nil {
		t.Fatal("QueryEvents with no org context returned rows; want ErrNoOrgContext")
	}
}

// TestRecordEventStampsTheCallersTenant: the write side. Under the v142 belt a
// row whose org_id disagrees with app.org_id is refused outright, so a writer
// that takes the org from anywhere but the context loses the record.
func TestRecordEventStampsTheCallersTenant(t *testing.T) {
	uas, ctx, cleanup := newUnifiedAuditService(t)
	defer cleanup()

	bCtx := orgctx.With(ctx, orgctx.Org{ID: uaOrgB})
	if err := uas.RecordEvent(bCtx, "openidx", "user.kill_switch", "", "", "10.0.0.1", nil); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}

	var org string
	if err := uas.db.Pool.QueryRow(ctx,
		`SELECT org_id::text FROM unified_audit_events WHERE event_type = 'user.kill_switch'`).Scan(&org); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if org != uaOrgB {
		t.Errorf("row filed under org %s, want %s (the caller's)", org, uaOrgB)
	}
}

// TestRecordEventWithoutOrgFallsBackVisibly: an audit write must never fail the
// operation it records, so a missing org is not fatal — but the row has to land
// somewhere an operator can find it rather than vanishing or taking a NULL the
// NOT NULL column would reject.
func TestRecordEventWithoutOrgFallsBackVisibly(t *testing.T) {
	uas, ctx, cleanup := newUnifiedAuditService(t)
	defer cleanup()

	if _, err := uas.db.Pool.Exec(ctx,
		`INSERT INTO organizations (id, name) VALUES ($1,'primary') ON CONFLICT DO NOTHING`,
		orgctx.DefaultOrgID); err != nil {
		t.Fatalf("seed primary org: %v", err)
	}
	if err := uas.RecordEvent(ctx, "access-service", "agent.enrolled", "", "", "10.0.0.2", nil); err != nil {
		t.Fatalf("RecordEvent with no org context: %v", err)
	}

	var org string
	if err := uas.db.Pool.QueryRow(ctx,
		`SELECT org_id::text FROM unified_audit_events WHERE event_type = 'agent.enrolled'`).Scan(&org); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if org != orgctx.DefaultOrgID {
		t.Errorf("unattributed row filed under %s, want the primary org %s", org, orgctx.DefaultOrgID)
	}
}
