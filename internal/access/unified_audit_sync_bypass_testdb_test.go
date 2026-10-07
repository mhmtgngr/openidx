package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/resilience"
)

// The external audit sync is install-wide: one poll ingests every tenant's
// Ziti events and Guacamole sessions and stamps each row with the org of the
// route it belongs to. Every comment on the two ingest paths says the sync
// "runs under WithBypassRLS", and the manual-sync endpoint does wrap its
// context — but the five-minute background loop in cmd/access-service handed
// the function a bare context.Background(). Under the FORCE RLS policy on
// unified_audit_events (v138–v165) that connection carries neither an org nor
// the bypass, so every insert was refused with 42501, the cursor was held, and
// no remote session or fabric event reached the audit trail — on a box that
// was otherwise healthy. The call site was the only thing standing between the
// contract and the policy; the contract now lives in the function itself.
//
// The test database runs as a superuser, which RLS never binds, so the policy
// is stood in for by a trigger that refuses the same thing the policy refuses:
// an insert on a connection that does not carry app.bypass_rls = 'on'. Both
// probes read the GUC the pool's checkout hook stamps, so what is asserted is
// exactly what production sees.
const unifiedAuditSyncSchema = `
CREATE TABLE IF NOT EXISTS external_audit_sync_state (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	source VARCHAR(50) UNIQUE NOT NULL,
	last_sync_at TIMESTAMPTZ,
	last_event_id VARCHAR(255),
	sync_cursor JSONB DEFAULT '{}',
	error_message TEXT,
	updated_at TIMESTAMPTZ DEFAULT NOW());
INSERT INTO external_audit_sync_state (source) VALUES ('guacamole') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS guacamole_connections (
	id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	route_id UUID REFERENCES proxy_routes(id) ON DELETE CASCADE,
	guacamole_connection_id VARCHAR(255) NOT NULL,
	protocol VARCHAR(20) NOT NULL,
	hostname VARCHAR(255) NOT NULL,
	port INTEGER NOT NULL,
	UNIQUE(route_id));
CREATE OR REPLACE FUNCTION refuse_unless_bypass() RETURNS trigger AS $$
BEGIN
	IF current_setting('app.bypass_rls', true) IS DISTINCT FROM 'on' THEN
		RAISE EXCEPTION 'new row violates row-level security policy for table "unified_audit_events"'
			USING ERRCODE = '42501';
	END IF;
	RETURN NEW;
END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS unified_audit_events_rls_stand_in ON unified_audit_events;
CREATE TRIGGER unified_audit_events_rls_stand_in
	BEFORE INSERT ON unified_audit_events
	FOR EACH ROW EXECUTE FUNCTION refuse_unless_bypass();
`

// sessionHistoryBroker is a Guacamole server whose history endpoint reports one
// finished RDP session on connection "7".
func sessionHistoryBroker(t *testing.T) *GuacamoleClient {
	t.Helper()
	start := time.Now().Add(-10 * time.Minute).UnixMilli()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/session/data/postgresql/history/connections" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"connectionIdentifier":"7","connectionName":"db-01","protocol":"rdp",` +
			`"username":"alice","remoteHost":"10.0.0.9","startDate":` + strconv.FormatInt(start, 10) + `,"endDate":` + strconv.FormatInt(start+60_000, 10) + `}]`))
	}))
	t.Cleanup(srv.Close)
	return &GuacamoleClient{
		baseURL: srv.URL, publicBaseURL: srv.URL, dataSource: "postgresql", authToken: "stub-token",
		httpClient: resilience.NewResilientHTTPClient(&http.Client{Timeout: 5 * time.Second}, guacBreaker("test", zap.NewNop())),
		logger:     zap.NewNop(), component: "guacamole",
	}
}

// TestExternalAuditSyncIngestsUnderTheRLSBypass is the regression test for the
// silent ingest failure: the sync is given the bare background context the
// service loop gives it, and the session must still land, attributed to the
// route's tenant, with the cursor advanced.
func TestExternalAuditSyncIngestsUnderTheRLSBypass(t *testing.T) {
	uas, ctx, cleanup := newUnifiedAuditService(t)
	defer cleanup()
	if _, err := uas.db.Pool.Exec(ctx, unifiedAuditSyncSchema); err != nil {
		t.Fatalf("apply sync schema: %v", err)
	}
	var routeID string
	if err := uas.db.Pool.QueryRow(ctx,
		`INSERT INTO proxy_routes (org_id, name) VALUES ($1, 'db-01') RETURNING id::text`, uaOrgA).Scan(&routeID); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	if _, err := uas.db.Pool.Exec(ctx,
		`INSERT INTO guacamole_connections (route_id, guacamole_connection_id, protocol, hostname, port)
		 VALUES ($1, '7', 'rdp', 'db-01', 3389)`, routeID); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	uas.SetGuacamoleClient(sessionHistoryBroker(t))

	// The service loop's context: no org, no bypass marker.
	if err := uas.SyncExternalAuditEvents(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	var n int
	var org string
	err := uas.db.Pool.QueryRow(ctx,
		`SELECT count(*), coalesce(min(org_id::text), '') FROM unified_audit_events WHERE source = 'guacamole'`).Scan(&n, &org)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("want the one Guacamole session recorded, got %d rows: the sync did not run under the RLS bypass", n)
	}
	if org != uaOrgA {
		t.Fatalf("session attributed to org %q, want the route's org %q", org, uaOrgA)
	}
	var cursor *time.Time
	if err := uas.db.Pool.QueryRow(ctx,
		`SELECT last_sync_at FROM external_audit_sync_state WHERE source = 'guacamole'`).Scan(&cursor); err != nil {
		t.Fatalf("cursor: %v", err)
	}
	if cursor == nil {
		t.Fatal("the sync cursor was not advanced after a fully ingested window")
	}
}
