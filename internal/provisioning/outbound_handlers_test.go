package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// newOutboundTestRouter builds a gin engine with only the outbound-SCIM target
// routes wired, backed by the given service. No auth middleware so tests hit the
// handlers directly.
func newOutboundTestRouter(svc *Service) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/provisioning")
	svc.registerOutboundRoutes(grp)
	return r
}

func doJSON(t *testing.T, r http.Handler, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestOutboundHandlersCRUD(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	if _, err := db.Pool.Exec(ctx, outboundSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	svc := &Service{db: db, logger: zap.NewNop()}
	r := newOutboundTestRouter(svc)

	// Create.
	w := doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets", TargetAppInput{
		Name: "slack", BaseURL: "https://api.slack.com/scim/v2", AuthType: "bearer",
		BearerToken: "xoxb-secret", ProvisionUsers: true, DeprovisionAction: "deactivate", Enabled: true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created TargetApp
	json.Unmarshal(w.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatal("expected target id")
	}
	// Secret must not leak in the response.
	if bytes.Contains(w.Body.Bytes(), []byte("xoxb-secret")) {
		t.Error("bearer token leaked in create response")
	}

	// List.
	w = doJSON(t, r, http.MethodGet, "/api/v1/provisioning/targets", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	var listResp struct {
		Targets []TargetApp `json:"targets"`
	}
	json.Unmarshal(w.Body.Bytes(), &listResp)
	if len(listResp.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(listResp.Targets))
	}

	// Get.
	w = doJSON(t, r, http.MethodGet, "/api/v1/provisioning/targets/"+created.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", w.Code)
	}

	// Update (rename, omit secret -> must be preserved).
	w = doJSON(t, r, http.MethodPut, "/api/v1/provisioning/targets/"+created.ID, TargetAppInput{
		Name: "slack-prod", ProvisionUsers: true, Enabled: true,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var updated TargetApp
	json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.Name != "slack-prod" {
		t.Errorf("expected renamed target, got %q", updated.Name)
	}
	// Secret still decrypts (was preserved through the update).
	tok, _ := svc.bearerTokenFor(ctx, created.ID)
	if tok != "xoxb-secret" {
		t.Errorf("secret not preserved on update, got %q", tok)
	}

	// Status.
	w = doJSON(t, r, http.MethodGet, "/api/v1/provisioning/targets/"+created.ID+"/status", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status: expected 200, got %d", w.Code)
	}

	// Delete.
	w = doJSON(t, r, http.MethodDelete, "/api/v1/provisioning/targets/"+created.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d", w.Code)
	}
	// Gone.
	w = doJSON(t, r, http.MethodGet, "/api/v1/provisioning/targets/"+created.ID, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", w.Code)
	}
}

func TestOutboundHandlerTestConnection(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, outboundSchema)

	// A fake SP that accepts the token and advertises patch support.
	sp := newFakeSP()
	srv := sp.server()
	defer srv.Close()

	svc := &Service{db: db, logger: zap.NewNop()}
	r := newOutboundTestRouter(svc)

	w := doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets", TargetAppInput{
		Name: "fake", BaseURL: srv.URL, AuthType: "bearer", BearerToken: "tok",
		ProvisionUsers: true, Enabled: true,
	})
	var created TargetApp
	json.Unmarshal(w.Body.Bytes(), &created)

	w = doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets/"+created.ID+"/test", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("test: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var res struct {
		OK             bool `json:"ok"`
		PatchSupported bool `json:"patch_supported"`
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if !res.OK {
		t.Errorf("expected ok=true from reachable SP, got %s", w.Body.String())
	}
}

func TestOutboundHandlerSyncEnqueues(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	db.Pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto`)
	db.Pool.Exec(ctx, outboundSchema)
	// Minimal users table for the full-sync SELECT.
	db.Pool.Exec(ctx, `CREATE TABLE users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username VARCHAR(255), email VARCHAR(255), first_name VARCHAR(255), last_name VARCHAR(255),
        enabled BOOLEAN DEFAULT true, org_id UUID)`)
	db.Pool.Exec(ctx, `INSERT INTO users (username,email,enabled) VALUES ('a@a','a@a',true),('b@b','b@b',true)`)

	svc := &Service{db: db, logger: zap.NewNop()}
	r := newOutboundTestRouter(svc)

	w := doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets", TargetAppInput{
		Name: "sync-target", BaseURL: "https://x/scim", AuthType: "bearer", BearerToken: "t",
		ProvisionUsers: true, Enabled: true,
	})
	var created TargetApp
	json.Unmarshal(w.Body.Bytes(), &created)

	w = doJSON(t, r, http.MethodPost, "/api/v1/provisioning/targets/"+created.ID+"/sync", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("sync: expected 202, got %d: %s", w.Code, w.Body.String())
	}
	var res struct {
		Enqueued int `json:"enqueued"`
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res.Enqueued != 2 {
		t.Errorf("expected 2 users enqueued for full sync, got %d", res.Enqueued)
	}
}
