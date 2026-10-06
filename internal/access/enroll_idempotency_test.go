package access

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap"
)

// enrolledAgentsSchema is the minimal enrolled_agents table (with the v92
// device_fingerprint column + partial unique index) needed to exercise
// issueAgentCredentials idempotency.
var enrolledAgentsSchema = []string{
	`CREATE TABLE IF NOT EXISTS enrolled_agents (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		agent_id TEXT UNIQUE NOT NULL,
		device_id TEXT NOT NULL,
		ziti_identity_id TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		auth_token_hash TEXT,
		enrolled_at TIMESTAMPTZ DEFAULT NOW(),
		last_seen_at TIMESTAMPTZ,
		last_report_at TIMESTAMPTZ,
		compliance_status TEXT NOT NULL DEFAULT 'unknown',
		compliance_score DOUBLE PRECISION,
		metadata JSONB,
		created_by TEXT,
		platform TEXT,
		form_factor TEXT,
		is_device_owner BOOLEAN NOT NULL DEFAULT false,
		enrollment_method TEXT,
		enrolled_by_user_id UUID,
		management_mode TEXT,
		known_device_id UUID,
		device_fingerprint TEXT,
		org_id UUID NOT NULL
	)`,
	// v197: the stable-identity key is per-tenant.
	`CREATE UNIQUE INDEX IF NOT EXISTS enrolled_agents_org_device_fingerprint_key
		ON enrolled_agents (org_id, device_fingerprint) WHERE device_fingerprint IS NOT NULL`,
}

// Two tenants for the idempotency tests: the stable-identity lookup is within
// the tenant the token names (v197), so the same physical machine enrolled by
// two tenants is two agents, and re-enrolment within one tenant is still one.
const (
	idemOrgA = "00000000-0000-0000-0000-00000000aa01"
	idemOrgB = "00000000-0000-0000-0000-00000000bb02"
)

// mustIssue enrols req into orgID by token and fails the test on a refusal.
// Only a fingerprint naming a revoked agent is refused, and none of its
// callers names one.
func mustIssue(t *testing.T, h *AgentAPIHandler, ctx context.Context, req enrollRequest, orgID string) issuedAgentCredentials {
	t.Helper()
	creds, err := h.issueAgentCredentials(ctx, req, "token", "", orgID)
	if err != nil {
		t.Fatalf("enrolment of %q into %s was refused: %v", req.DeviceFingerprint, orgID, err)
	}
	return creds
}

// TestEnrollIdempotentByFingerprint is the regression test for the "one agent
// per physical device" fix: two enrollments carrying the same
// device_fingerprint must reuse a single agent_id / row (rotating only the auth
// token), instead of piling up a new enrolled_agents row per install.
func TestEnrollIdempotentByFingerprint(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}

	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	req := enrollRequest{
		Hostname:          "DANA-PC",
		OS:                "windows",
		Platform:          "windows",
		DeviceFingerprint: "win:abc123",
	}

	first := mustIssue(t, h, ctx, req, idemOrgA)
	if first.AgentID == "" {
		t.Fatal("first enroll returned empty agent_id")
	}
	second := mustIssue(t, h, ctx, req, idemOrgA)

	if second.AgentID != first.AgentID {
		t.Errorf("re-enroll minted a new agent_id: %q then %q", first.AgentID, second.AgentID)
	}
	if second.DeviceID != first.DeviceID {
		t.Errorf("re-enroll changed device_id: %q then %q", first.DeviceID, second.DeviceID)
	}
	if second.AuthToken == "" || second.AuthToken == first.AuthToken {
		t.Errorf("re-enroll should rotate the auth token (got %q, prev %q)", second.AuthToken, first.AuthToken)
	}

	var rows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM enrolled_agents WHERE device_fingerprint = $1`, req.DeviceFingerprint).
		Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("expected exactly 1 row for the fingerprint, got %d", rows)
	}
}

// TestEnrollDistinctFingerprintsDistinctAgents confirms different devices still
// get different agent_ids (the idempotency is scoped to the fingerprint).
func TestEnrollDistinctFingerprintsDistinctAgents(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)

	a := mustIssue(t, h, ctx, enrollRequest{Hostname: "A", DeviceFingerprint: "win:aaa"}, idemOrgA)
	b := mustIssue(t, h, ctx, enrollRequest{Hostname: "B", DeviceFingerprint: "win:bbb"}, idemOrgA)
	if a.AgentID == b.AgentID {
		t.Errorf("distinct fingerprints shared an agent_id: %q", a.AgentID)
	}

	// And a legacy enroll (no fingerprint) always gets a fresh row.
	c1 := mustIssue(t, h, ctx, enrollRequest{Hostname: "C"}, idemOrgA)
	c2 := mustIssue(t, h, ctx, enrollRequest{Hostname: "C"}, idemOrgA)
	if c1.AgentID == c2.AgentID {
		t.Errorf("legacy fingerprint-less enroll should NOT dedupe: %q", c1.AgentID)
	}
}

// TestEnrollFingerprintIsPerTenant: one physical machine managed by two tenants
// is two agents (v197 made the fingerprint key (org_id, device_fingerprint)),
// and neither tenant's re-enrolment reaches into the other's row.
func TestEnrollFingerprintIsPerTenant(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)
	req := enrollRequest{Hostname: "SHARED-LAPTOP", DeviceFingerprint: "win:shared"}

	inA := mustIssue(t, h, ctx, req, idemOrgA)
	inB := mustIssue(t, h, ctx, req, idemOrgB)
	if inA.AgentID == "" || inB.AgentID == "" {
		t.Fatalf("enrolment minted no agent: A=%q B=%q", inA.AgentID, inB.AgentID)
	}
	if inA.AgentID == inB.AgentID {
		t.Fatalf("two tenants enrolling the same fingerprint shared one agent %q; the fleet is per-tenant", inA.AgentID)
	}
	againA := mustIssue(t, h, ctx, req, idemOrgA)
	if againA.AgentID != inA.AgentID {
		t.Errorf("tenant A's re-enrolment minted %q, want its own %q", againA.AgentID, inA.AgentID)
	}
	var orgOfA, orgOfB string
	if err := db.Pool.QueryRow(ctx, `SELECT org_id::text FROM enrolled_agents WHERE agent_id = $1`, inA.AgentID).Scan(&orgOfA); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT org_id::text FROM enrolled_agents WHERE agent_id = $1`, inB.AgentID).Scan(&orgOfB); err != nil {
		t.Fatal(err)
	}
	if orgOfA != idemOrgA || orgOfB != idemOrgB {
		t.Errorf("agents carry org %q and %q, want %q and %q", orgOfA, orgOfB, idemOrgA, idemOrgB)
	}
}

// TestReenrolmentDoesNotUndoARevoke is the function-level half of the revoke
// fix; every enrolment path goes through issueAgentCredentials, and the
// handler-level tests are in agent_reenrol_revoked_testdb_test.go.
//
// A fingerprint that names a revoked agent is refused with revokedAgentError
// naming that agent, and the row is left exactly as the revoke left it: same
// status, same token hash, no new row. A suspended or pending row re-enrols to
// active as before, under the same agent id with a rotated token.
func TestReenrolmentDoesNotUndoARevoke(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	for _, stmt := range enrolledAgentsSchema {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	h := NewAgentAPIHandler(zap.NewNop(), db, nil, nil)

	type row struct{ status, hash string }
	read := func(agentID string) row {
		t.Helper()
		var r row
		if err := db.Pool.QueryRow(ctx,
			`SELECT status, auth_token_hash FROM enrolled_agents WHERE agent_id = $1`, agentID).
			Scan(&r.status, &r.hash); err != nil {
			t.Fatalf("read %s: %v", agentID, err)
		}
		return r
	}

	revokedReq := enrollRequest{Hostname: "LOST-LAPTOP", DeviceFingerprint: "win:revoked"}
	first := mustIssue(t, h, ctx, revokedReq, idemOrgA)
	if _, err := db.Pool.Exec(ctx,
		`UPDATE enrolled_agents SET status = 'revoked' WHERE agent_id = $1`, first.AgentID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	before := read(first.AgentID)

	creds, err := h.issueAgentCredentials(ctx, revokedReq, "token", "", idemOrgA)
	var revoked revokedAgentError
	if !errors.As(err, &revoked) {
		t.Fatalf("re-enrolling a revoked fingerprint answered (%+v, %v), want revokedAgentError", creds, err)
	}
	if revoked.agentID != first.AgentID {
		t.Errorf("the refusal names agent %q, want the revoked %q", revoked.agentID, first.AgentID)
	}
	if creds.AuthToken != "" || creds.AgentID != "" {
		t.Errorf("a refused enrolment still handed out credentials: %+v", creds)
	}
	if after := read(first.AgentID); after != before {
		t.Errorf("the refused enrolment changed the revoked row: %+v -> %+v", before, after)
	}
	var rows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM enrolled_agents WHERE device_fingerprint = $1`, revokedReq.DeviceFingerprint).
		Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("the refused enrolment left %d rows for the fingerprint, want 1", rows)
	}

	// The revoke is per tenant, like the fingerprint key: the same machine in
	// another tenant is another agent, and enrols there.
	if other := mustIssue(t, h, ctx, revokedReq, idemOrgB); other.AgentID == first.AgentID {
		t.Errorf("tenant B's enrolment reused tenant A's revoked agent %q", first.AgentID)
	}

	for _, status := range []string{"suspended", "pending", "active"} {
		t.Run("a "+status+" row still re-enrols", func(t *testing.T) {
			req := enrollRequest{Hostname: "PC", DeviceFingerprint: "win:" + status}
			was := mustIssue(t, h, ctx, req, idemOrgA)
			if _, err := db.Pool.Exec(ctx,
				`UPDATE enrolled_agents SET status = $2 WHERE agent_id = $1`, was.AgentID, status); err != nil {
				t.Fatalf("set status: %v", err)
			}
			again := mustIssue(t, h, ctx, req, idemOrgA)
			if again.AgentID != was.AgentID || again.AuthToken == was.AuthToken {
				t.Errorf("re-enrolment gave agent %q token-rotated=%t, want agent %q with a new token",
					again.AgentID, again.AuthToken != was.AuthToken, was.AgentID)
			}
			if r := read(was.AgentID); r.status != "active" || r.hash != sha256Hex(again.AuthToken) {
				t.Errorf("after re-enrolment the row is %q holding another token, want active with the new one", r.status)
			}
		})
	}
}
