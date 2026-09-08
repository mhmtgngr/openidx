package governance

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/vault"
)

// Returning a checked-out credential does two things that have to agree: it
// revokes the vault grant, and it marks the request no longer fulfilled. The
// revoke was checked; the mark was `_, _ = s.db.Pool.Exec(...)`. So a failed
// UPDATE produced a request still reading 'fulfilled' -- the console still
// shows the credential checked out to this user and the JIT expiry sweep still
// counts it as held -- under a 200 {"status":"returned"} and an audit event
// saying jit_credential.checkout_returned / success.
//
// That is the certification failure in miniature: the record says the access
// was handed back while the record it is drawn from says it is still out. The
// grant IS gone by then, so the safe direction is to report the failure and let
// the caller retry (the 'fulfilled' gate still admits a retry), never to report
// the return that did not finish.

const (
	rcOrg    = "00000000-0000-0000-0000-0000000000c0"
	rcUser   = "00000000-0000-0000-0000-0000000000c1"
	rcReq    = "00000000-0000-0000-0000-0000000000c2"
	rcSecret = "00000000-0000-0000-0000-0000000000c3"
)

type returnFixture struct {
	t   *testing.T
	svc *Service
	db  *database.PostgresDB
	ctx context.Context
}

func newReturnFixture(t *testing.T) *returnFixture {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: rcOrg})
	if _, err := db.Pool.Exec(ctx, `
		CREATE TABLE access_requests (
			id UUID PRIMARY KEY, requester_id UUID, resource_type VARCHAR(50),
			resource_id UUID, resource_name VARCHAR(255), org_id UUID,
			status VARCHAR(30), updated_at TIMESTAMPTZ DEFAULT now());
		CREATE TABLE vault_access_grants (
			secret_id UUID, principal_type VARCHAR(20), principal_id UUID, org_id UUID);
		CREATE TABLE credential_rotation_policies (
			secret_id UUID, org_id UUID, rotate_on_checkout BOOLEAN, next_run_at TIMESTAMPTZ);
		CREATE TABLE audit_events (
			id UUID PRIMARY KEY, event_type VARCHAR(50), category VARCHAR(50), action VARCHAR(100),
			outcome VARCHAR(20), actor_id UUID, actor_ip VARCHAR(45), target_id UUID,
			target_type VARCHAR(50), details JSONB, created_at TIMESTAMPTZ, org_id UUID);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	f := &returnFixture{t: t, ctx: ctx, db: db}
	f.exec(`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, org_id, status)
	        VALUES ($1, $2, 'vault_credential', $3, 'db-root', $4, 'fulfilled')`, rcReq, rcUser, rcSecret, rcOrg)
	f.exec(`INSERT INTO vault_access_grants (secret_id, principal_type, principal_id, org_id)
	        VALUES ($1, 'user', $2, $3)`, rcSecret, rcUser, rcOrg)

	ring, err := vault.KeyringFromConfig(vault.KeyConfig{
		KEK: base64.StdEncoding.EncodeToString([]byte("return-credential-test-kek-01234")),
	})
	if err != nil {
		t.Fatalf("vault keyring: %v", err)
	}
	vaultSvc, err := vault.NewService(db, ring, nil, time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("vault service: %v", err)
	}

	f.svc = &Service{db: db, logger: zap.NewNop(), vaultSvc: vaultSvc}
	return f
}

func (f *returnFixture) exec(q string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.db.Pool.Exec(f.ctx, q, args...); err != nil {
		f.t.Fatalf("exec (%s): %v", q, err)
	}
}

func (f *returnFixture) scalar(q string, args ...interface{}) string {
	f.t.Helper()
	var v string
	if err := f.db.Pool.QueryRow(f.ctx, q, args...).Scan(&v); err != nil {
		f.t.Fatalf("scalar (%s): %v", q, err)
	}
	return v
}

func (f *returnFixture) count(q string, args ...interface{}) int {
	f.t.Helper()
	var n int
	if err := f.db.Pool.QueryRow(f.ctx, q, args...).Scan(&n); err != nil {
		f.t.Fatalf("count (%s): %v", q, err)
	}
	return n
}

// refuseRequestUpdates makes UPDATE on access_requests impossible while leaving
// the handler's SELECT and the vault revoke working, so the test reproduces
// exactly the half-done return: grant gone, record not marked.
func (f *returnFixture) refuseRequestUpdates() {
	f.exec(`CREATE OR REPLACE FUNCTION refuse_request_update() RETURNS trigger AS $$
	        BEGIN RAISE EXCEPTION 'request updates are refused in this test'; END; $$ LANGUAGE plpgsql`)
	f.exec(`CREATE TRIGGER no_request_update BEFORE UPDATE ON access_requests
	        FOR EACH ROW EXECUTE FUNCTION refuse_request_update()`)
}

func (f *returnFixture) returnCredential() *httptest.ResponseRecorder {
	f.t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/governance/requests/"+rcReq+"/return", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req.WithContext(f.ctx)
	c.Params = gin.Params{{Key: "id", Value: rcReq}}
	c.Set("user_id", rcUser)
	f.svc.handleReturnCredential(c)
	return w
}

func TestReturningACredentialMarksTheRequestReturned(t *testing.T) {
	f := newReturnFixture(t)

	w := f.returnCredential()

	if w.Code != http.StatusOK {
		t.Fatalf("return answered %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := f.scalar(`SELECT status FROM access_requests WHERE id=$1`, rcReq); got != "expired" {
		t.Errorf("request status is %q after a successful return; want expired", got)
	}
	if n := f.count(`SELECT COUNT(*) FROM vault_access_grants WHERE secret_id=$1 AND principal_id=$2`, rcSecret, rcUser); n != 0 {
		t.Errorf("the vault grant survived the return (%d rows)", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM audit_events WHERE action='jit_credential.checkout_returned'`); n != 1 {
		t.Errorf("expected one checkout_returned audit event, got %d", n)
	}
}

func TestAReturnThatCannotMarkTheRequestIsNotReportedAsReturned(t *testing.T) {
	f := newReturnFixture(t)
	f.refuseRequestUpdates()

	w := f.returnCredential()

	if w.Code == http.StatusOK {
		t.Errorf("a return that could not mark the request answered 200 %s; the credential still reads as checked out to this user",
			w.Body.String())
	}
	if got := f.scalar(`SELECT status FROM access_requests WHERE id=$1`, rcReq); got != "fulfilled" {
		t.Fatalf("fixture broken: status is %q, expected the refused UPDATE to leave it fulfilled", got)
	}
	// The audit trail must not claim a return that the record does not show.
	if n := f.count(`SELECT COUNT(*) FROM audit_events WHERE action='jit_credential.checkout_returned'`); n != 0 {
		t.Errorf("%d checkout_returned audit events were written for a return that did not complete", n)
	}
}
