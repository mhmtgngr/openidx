package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Tenant isolation for the developer portal, migration v156.
//
// ONE ROW FOR THE WHOLE INSTALLATION, KEYED ON A STRING LITERAL. v54 declared
// `setting_key VARCHAR(100) UNIQUE NOT NULL` and both handlers use the constant
// 'global':
//
//	SELECT setting_value FROM developer_settings WHERE setting_key = 'global'
//	INSERT ... VALUES ('global', $1, NOW()) ON CONFLICT (setting_key) DO UPDATE ...
//
// So there was exactly one settings row and every organization's administrators
// shared it. The last one to press Save chose, for everybody, the maximum API
// keys per user, which scopes an API key may carry, the webhook IP allowlist,
// the CORS allowed origins, the default rate limit, and whether sandbox mode is
// on.
//
// THE PLAYGROUND SESSION holds `code_verifier` — the PKCE secret that lets its
// authorization code be redeemed — and was fetched by id alone: no tenant term,
// no owner term, and no role check at all, though every other handler in that
// file calls requireAdmin.
func TestDeveloperPortal_TenantIsolation(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool, zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('dev-b','dev-b') RETURNING id::text`).Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	s := &Service{db: db, logger: zap.NewNop()}

	// Real rows: oauth_playground_sessions.user_id is a foreign key, and the
	// owner check below is only meaningful against users that exist.
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			org, name+"-"+suffix, name+"-"+suffix+"@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	userA := seedUser(orgA, "dev-a-admin")
	userB := seedUser(orgB, "dev-b-admin")

	call := func(handler gin.HandlerFunc, org, who, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
		c.Request = r.WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
		c.Set("roles", []string{"admin"})
		c.Set("user_id", who)
		handler(c)
		return w
	}

	// THE SHARED SETTINGS ROW. Each organization saves its own values and reads
	// its own back — which the single 'global' row made impossible.
	t.Run("each organization keeps its own developer settings", func(t *testing.T) {
		saveA := call(s.handleUpdateDeveloperSettings, orgA, userA, "PUT", "/developer/settings",
			`{"api_key_max_per_user":3,"rate_limit_default":50,"cors_allowed_origins":["https://a.example.test"],"sandbox_enabled":false}`)
		if saveA.Code != 200 {
			t.Fatalf("org A save: status %d, body %s", saveA.Code, saveA.Body.String())
		}
		saveB := call(s.handleUpdateDeveloperSettings, orgB, userB, "PUT", "/developer/settings",
			`{"api_key_max_per_user":99,"rate_limit_default":9999,"cors_allowed_origins":["https://evil.example.test"],"sandbox_enabled":true}`)
		if saveB.Code != 200 {
			t.Fatalf("org B save: status %d, body %s", saveB.Code, saveB.Body.String())
		}

		read := func(org, who string) DeveloperSettings {
			t.Helper()
			w := call(s.handleGetDeveloperSettings, org, who, "GET", "/developer/settings", "")
			if w.Code != 200 {
				t.Fatalf("read as %s: status %d, body %s", org, w.Code, w.Body.String())
			}
			var out DeveloperSettings
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("bad json: %v", err)
			}
			return out
		}
		gotA, gotB := read(orgA, userA), read(orgB, userB)

		if gotA.RateLimitDefault != 50 || gotA.APIKeyMaxPerUser != 3 {
			t.Errorf("org A read back org B's settings: rate_limit=%d max_keys=%d. "+
				"setting_key was UNIQUE across the installation and both handlers "+
				"use the literal 'global', so there was one row and the last "+
				"administrator to press Save chose the API-key limits, the CORS "+
				"origins and the rate limit for every organization",
				gotA.RateLimitDefault, gotA.APIKeyMaxPerUser)
		}
		if gotA.SandboxEnabled {
			t.Error("org B turned sandbox mode on for org A")
		}
		if len(gotA.CORSAllowedOrigins) != 1 || gotA.CORSAllowedOrigins[0] != "https://a.example.test" {
			t.Errorf("org A's CORS allowlist is %v; org B chose it", gotA.CORSAllowedOrigins)
		}
		// And the predicate must scope, not empty: org B still has its own.
		if gotB.RateLimitDefault != 9999 {
			t.Errorf("org B lost its own settings (rate_limit=%d)", gotB.RateLimitDefault)
		}
	})

	// THE PKCE VERIFIER.
	t.Run("a playground session is not readable by another tenant", func(t *testing.T) {
		w := call(s.handleCreatePlaygroundSession, orgA, userA, "POST", "/developer/playground/sessions", "")
		if w.Code != 201 {
			t.Fatalf("create as org A: status %d, body %s", w.Code, w.Body.String())
		}
		var created PlaygroundSession
		if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if created.CodeVerifier == "" {
			t.Fatal("no code verifier on the created session")
		}

		// v54 indexed user_id and the insert never set it. It must be set now,
		// or the owner check below is checking nothing.
		var owner *string
		if err := db.Pool.QueryRow(ctx,
			`SELECT user_id::text FROM oauth_playground_sessions WHERE id = $1::uuid`,
			created.ID).Scan(&owner); err != nil {
			t.Fatalf("read back session: %v", err)
		}
		if owner == nil || *owner != userA {
			t.Fatalf("the session's user_id is %v, want %s. v54 created the column and "+
				"an index on it and no insert ever wrote it -- an index on a value "+
				"that is always NULL", owner, userA)
		}

		body := fmt.Sprintf(`{"session_id":%q,"step":"authorize"}`, created.ID)

		other := call(s.handleExecutePlayground, orgB, userB, "POST", "/developer/playground/execute", body)
		if other.Code == 200 {
			t.Error("org B executed a step on org A's playground session. The row holds " +
				"the PKCE verifier that lets that session's authorization code be " +
				"redeemed")
		}

		// A different administrator inside the same organization is also not
		// the owner.
		colleague := call(s.handleExecutePlayground, orgA, userB, "POST", "/developer/playground/execute", body)
		if colleague.Code == 200 {
			t.Error("another administrator in the same organization executed a step on " +
				"a session they do not own")
		}

		// The owner still can: the terms must scope, not deny outright.
		own := call(s.handleExecutePlayground, orgA, userA, "POST", "/developer/playground/execute", body)
		if own.Code == 404 {
			t.Errorf("the session's own creator could not execute a step: %s", own.Body.String())
		}
	})

	// THE MISSING ROLE CHECK. Every other handler in this file has one.
	t.Run("the playground requires an administrator", func(t *testing.T) {
		for name, h := range map[string]gin.HandlerFunc{
			"create":  s.handleCreatePlaygroundSession,
			"execute": s.handleExecutePlayground,
		} {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/developer/playground", bytes.NewBufferString(`{}`)).
				WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
			c.Set("roles", []string{"user"}) // authenticated, not an administrator
			c.Set("user_id", userA)
			h(c)
			if w.Code != 403 {
				t.Errorf("%s with a non-admin role returned %d, expected 403: %s",
					name, w.Code, w.Body.String())
			}
		}
	})

	// The direction of a failure.
	t.Run("no organization is a refusal, not the shared row", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/developer/settings", nil) // bare context
		c.Set("roles", []string{"admin"})
		s.handleGetDeveloperSettings(c)
		if w.Code != 403 {
			t.Fatalf("reading developer settings with no organization returned %d: %s",
				w.Code, w.Body.String())
		}
	})

}
