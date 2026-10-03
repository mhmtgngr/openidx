package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Invariant I8 of the third-party access framework at the request: an external
// (vendor) user asks for access that ends, and ends no later than the account.
// The test files requests through handleCreateAccessRequest on the migrated
// schema for an external user whose account ends in ten days: a permanent
// request and a 30-day one are refused with 400 external_window_invalid and
// leave no request behind; a 7-day one is filed with its end. An internal
// user's permanent request is filed as before.
func TestAnExternalUsersRequestEndsWithTheAccount(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gin.SetMode(gin.TestMode)
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	internal := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "win-sponsor-"+suffix)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "Acme "+suffix)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '10 days')
		RETURNING id::text`, org, "win-vendor-"+suffix, vendor, internal)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	requester := external
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Set("user_id", requester)
		c.Next()
	})
	r.POST("/requests", s.handleCreateAccessRequest)
	request := func(duration string) (int, map[string]interface{}) {
		t.Helper()
		body := `{"resource_type":"application","resource_name":"Ticketing","justification":"vendor support"`
		if duration != "" {
			body += `,"duration":"` + duration + `"`
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/requests", strings.NewReader(body+"}"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	filed := func(userID string) string {
		return scalar(`SELECT count(*)::text FROM access_requests WHERE requester_id = $1 AND org_id = $2`, userID, org)
	}

	for _, d := range []string{"", "30d"} {
		code, body := request(d)
		if code != http.StatusBadRequest || body["code"] != "external_window_invalid" {
			t.Errorf("an external user's request for %q: %d %v, want 400 external_window_invalid", d, code, body)
		}
	}
	if n := filed(external); n != "0" {
		t.Fatalf("the refused requests left %s request(s) behind", n)
	}

	code, body := request("7d")
	if code != http.StatusCreated || body["expires_at"] == nil {
		t.Fatalf("an external user's 7-day request: %d %v, want 201 with its end", code, body)
	}

	requester = internal
	if code, body := request(""); code != http.StatusCreated {
		t.Errorf("an internal user's permanent request: %d %v, want 201", code, body)
	}
}
