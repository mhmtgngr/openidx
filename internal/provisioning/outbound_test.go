package provisioning

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
	"go.uber.org/zap"
)

// outboundSchema is the subset of migration v95 the worker/store tests need.
// Kept inline so the DB tests are self-contained (the sibling suites do the
// same for users/groups).
const outboundSchema = `
CREATE TABLE IF NOT EXISTS scim_target_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, name VARCHAR(255) NOT NULL,
    base_url TEXT NOT NULL, auth_type VARCHAR(32) NOT NULL DEFAULT 'bearer', auth_token_enc TEXT,
    oauth_token_url TEXT, oauth_client_id TEXT, oauth_client_secret_enc TEXT, oauth_scope TEXT,
    provision_users BOOLEAN NOT NULL DEFAULT true, provision_groups BOOLEAN NOT NULL DEFAULT false,
    deprovision_action VARCHAR(16) NOT NULL DEFAULT 'deactivate', attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT true, last_sync_at TIMESTAMPTZ, last_sync_status VARCHAR(32), last_sync_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS scim_provisioning_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID,
    target_id UUID NOT NULL REFERENCES scim_target_apps(id) ON DELETE CASCADE,
    resource_type VARCHAR(16) NOT NULL, local_id UUID NOT NULL, remote_id VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'pending', last_payload_hash VARCHAR(64), last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (target_id, resource_type, local_id));
CREATE TABLE IF NOT EXISTS scim_provisioning_queue (
    id BIGSERIAL PRIMARY KEY, org_id UUID, target_id UUID NOT NULL REFERENCES scim_target_apps(id) ON DELETE CASCADE,
    resource_type VARCHAR(16) NOT NULL, local_id UUID NOT NULL, operation VARCHAR(16) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb, state VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`

// fakeSP is a minimal in-memory SCIM service provider for the worker tests.
type fakeSP struct {
	mu       sync.Mutex
	users    map[string]map[string]interface{} // id -> resource
	nextID   int
	failNext bool // when set, the next create returns 500 (transient)
	created  int
	patched  int
	deleted  int
}

func newFakeSP() *fakeSP { return &fakeSP{users: map[string]map[string]interface{}{}} }

func (f *fakeSP) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/ServiceProviderConfig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		w.Write([]byte(`{"patch":{"supported":true}}`))
	})
	mux.HandleFunc("/Users", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failNext {
			f.failNext = false
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		f.nextID++
		id := "remote-" + itoaLocal(f.nextID)
		body["id"] = id
		f.users[id] = body
		f.created++
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/Users/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := strings.TrimPrefix(r.URL.Path, "/Users/")
		switch r.Method {
		case http.MethodPatch:
			f.patched++
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			body["id"] = id
			f.users[id] = body
			w.Header().Set("Content-Type", "application/scim+json")
			json.NewEncoder(w).Encode(body)
		case http.MethodDelete:
			delete(f.users, id)
			f.deleted++
			w.WriteHeader(http.StatusNoContent)
		}
	})
	return httptest.NewServer(mux)
}

func itoaLocal(n int) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestOutboundWorkerCreateThenDeactivate(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`); err != nil {
		t.Fatalf("pgcrypto: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, outboundSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	sp := newFakeSP()
	srv := sp.server()
	defer srv.Close()

	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}

	// Configure an enabled user-provisioning target pointing at the fake SP.
	target, err := svc.CreateTargetApp(ctx, "", &TargetAppInput{
		Name: "fake-saas", BaseURL: srv.URL, AuthType: "bearer", BearerToken: "tok",
		ProvisionUsers: true, DeprovisionAction: "deactivate", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateTargetApp: %v", err)
	}

	userID := "11111111-1111-1111-1111-111111111111"
	snap := userSnapshot{ID: userID, UserName: "alice@corp.com", Email: "alice@corp.com",
		FirstName: "Alice", LastName: "Smith", Active: true, Department: "Eng"}

	// Enqueue a create; expect exactly one queue row (one enabled target).
	n, err := svc.EnqueueUserOp(ctx, "", userID, OpCreate, snap)
	if err != nil {
		t.Fatalf("EnqueueUserOp: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 enqueued, got %d", n)
	}

	w := &outboundWorker{svc: svc, cfg: OutboundWorkerConfig{BatchSize: 10}, logger: zap.NewNop()}
	if _, err := w.drainBatch(ctx); err != nil {
		t.Fatalf("drainBatch: %v", err)
	}

	if sp.created != 1 {
		t.Errorf("expected 1 remote create, got %d", sp.created)
	}
	// Record should be active with a remote id.
	rec, err := w.loadRecord(ctx, target.ID, "user", userID)
	if err != nil || rec == nil {
		t.Fatalf("loadRecord: %v (rec=%v)", err, rec)
	}
	if rec.status != RecordActive || rec.remoteID == "" {
		t.Errorf("expected active record with remote id, got %+v", rec)
	}

	// Now deprovision: enqueue deactivate, drain, expect a PATCH.
	if _, err := svc.EnqueueUserOp(ctx, "", userID, OpDeactivate, snap); err != nil {
		t.Fatalf("enqueue deactivate: %v", err)
	}
	if _, err := w.drainBatch(ctx); err != nil {
		t.Fatalf("drainBatch deactivate: %v", err)
	}
	if sp.patched != 1 {
		t.Errorf("expected 1 remote patch (deactivate), got %d", sp.patched)
	}
	rec2, _ := w.loadRecord(ctx, target.ID, "user", userID)
	if rec2 == nil || rec2.status != RecordDeprovisioned {
		t.Errorf("expected deprovisioned record, got %+v", rec2)
	}

	// Queue should have no pending items left.
	var pending int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_provisioning_queue WHERE state='pending'`).Scan(&pending)
	if pending != 0 {
		t.Errorf("expected 0 pending queue items, got %d", pending)
	}
	var done int
	db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scim_provisioning_queue WHERE state='done'`).Scan(&done)
	if done != 2 {
		t.Errorf("expected 2 done queue items, got %d", done)
	}
}

func TestOutboundWorkerTransientRetry(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, outboundSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	sp := newFakeSP()
	sp.failNext = true // first create returns 500 -> should retry (not dead-letter)
	srv := sp.server()
	defer srv.Close()

	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}
	target, _ := svc.CreateTargetApp(ctx, "", &TargetAppInput{
		Name: "flaky", BaseURL: srv.URL, AuthType: "bearer", BearerToken: "tok",
		ProvisionUsers: true, DeprovisionAction: "deactivate", Enabled: true,
	})
	userID := "22222222-2222-2222-2222-222222222222"
	svc.EnqueueUserOp(ctx, "", userID, OpCreate, userSnapshot{ID: userID, UserName: "bob@corp.com", Active: true})

	w := &outboundWorker{svc: svc, cfg: OutboundWorkerConfig{BatchSize: 10}, logger: zap.NewNop()}
	w.drainBatch(ctx) // first attempt fails (500)

	// Item should be back to pending with attempts=1 and a future next_attempt_at.
	var state string
	var attempts int
	db.Pool.QueryRow(ctx, `SELECT state, attempts FROM scim_provisioning_queue WHERE target_id=$1`, target.ID).Scan(&state, &attempts)
	if state != QueuePending || attempts != 1 {
		t.Fatalf("expected pending/attempts=1 after transient failure, got %s/%d", state, attempts)
	}

	// Force it ready and drain again; now the SP succeeds.
	db.Pool.Exec(ctx, `UPDATE scim_provisioning_queue SET next_attempt_at = NOW() - interval '1 minute'`)
	w.drainBatch(ctx)
	if sp.created != 1 {
		t.Errorf("expected 1 create after retry, got %d", sp.created)
	}
	db.Pool.QueryRow(ctx, `SELECT state FROM scim_provisioning_queue WHERE target_id=$1`, target.ID).Scan(&state)
	if state != QueueDone {
		t.Errorf("expected done after successful retry, got %s", state)
	}
}

func TestOutboundWorkerDeadLetterTerminal(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, outboundSchema)

	// SP that always returns 400 on create (terminal).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/Users") && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"detail":"nope"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}
	target, _ := svc.CreateTargetApp(ctx, "", &TargetAppInput{
		Name: "bad", BaseURL: srv.URL, AuthType: "bearer", BearerToken: "tok",
		ProvisionUsers: true, Enabled: true,
	})
	userID := "33333333-3333-3333-3333-333333333333"
	svc.EnqueueUserOp(ctx, "", userID, OpCreate, userSnapshot{ID: userID, UserName: "eve@corp.com", Active: true})

	w := &outboundWorker{svc: svc, cfg: OutboundWorkerConfig{BatchSize: 10}, logger: zap.NewNop()}
	w.drainBatch(ctx)

	var state string
	db.Pool.QueryRow(ctx, `SELECT state FROM scim_provisioning_queue WHERE target_id=$1`, target.ID).Scan(&state)
	if state != QueueDead {
		t.Errorf("expected dead-letter on terminal 400, got %s", state)
	}
	// Record should be in error state.
	rec, _ := w.loadRecord(ctx, target.ID, "user", userID)
	if rec == nil || rec.status != RecordError {
		t.Errorf("expected error record, got %+v", rec)
	}
	_ = time.Now
}

func TestEnqueueFanOutOnlyEnabledUserTargets(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, outboundSchema)

	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}
	// enabled+users -> should receive; disabled -> skip; groups-only -> skip for user op.
	svc.CreateTargetApp(ctx, "", &TargetAppInput{Name: "a", BaseURL: "https://a/scim", ProvisionUsers: true, Enabled: true})
	svc.CreateTargetApp(ctx, "", &TargetAppInput{Name: "b", BaseURL: "https://b/scim", ProvisionUsers: true, Enabled: false})
	svc.CreateTargetApp(ctx, "", &TargetAppInput{Name: "c", BaseURL: "https://c/scim", ProvisionUsers: false, ProvisionGroups: true, Enabled: true})

	userID := "44444444-4444-4444-4444-444444444444"
	n, err := svc.EnqueueUserOp(ctx, "", userID, OpCreate, userSnapshot{ID: userID, UserName: "x@x", Active: true})
	if err != nil {
		t.Fatalf("EnqueueUserOp: %v", err)
	}
	if n != 1 {
		t.Errorf("expected fan-out to 1 enabled user target, got %d", n)
	}
}

func TestTargetAppSecretRoundTrip(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, outboundSchema)

	svc := &Service{db: db, logger: zap.NewNop(), config: &config.Config{}}
	target, err := svc.CreateTargetApp(ctx, "", &TargetAppInput{
		Name: "sec", BaseURL: "https://s/scim", AuthType: "bearer", BearerToken: "super-secret",
		ProvisionUsers: true, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateTargetApp: %v", err)
	}
	// GetTargetApp never returns the secret.
	got, _ := svc.GetTargetApp(ctx, "", target.ID)
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "super-secret") {
		t.Error("secret leaked through TargetApp JSON")
	}
	// bearerTokenFor decrypts it back.
	tok, err := svc.bearerTokenFor(ctx, target.ID)
	if err != nil {
		t.Fatalf("bearerTokenFor: %v", err)
	}
	if tok != "super-secret" {
		t.Errorf("expected decrypted token, got %q", tok)
	}
}
