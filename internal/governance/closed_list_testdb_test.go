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

// Invariants I11 and I5 of the third-party access framework at the request,
// on the migrated schema and through the real handler: an external user whose
// vendor is on a closed list asks only for what was opened to the vendor; with
// the list off they ask as before; an internal user is not held to any list;
// and an external user never asks for a vault credential.
func TestAnExternalUserOnAClosedListAsksOnlyForWhatIsOpen(t *testing.T) {
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
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
	}
	sponsor := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "cl-sponsor-"+suffix)
	operator := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "cl-operator-"+suffix)
	vendor := scalar(`INSERT INTO vendor_organizations (org_id, name, closed_list) VALUES ($1, $2, true) RETURNING id::text`, org, "Acme "+suffix)
	external := scalar(`
		INSERT INTO users (org_id, username, email, user_type, vendor_org_id, sponsor_user_id, account_expires_at)
		VALUES ($1, $2::text, $2::text || '@supplier.example.test', 'external', $3, $4, NOW() + interval '30 days')
		RETURNING id::text`, org, "cl-vendor-"+suffix, vendor, sponsor)
	entry := func(name string) string {
		id := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port)
			VALUES ($1, $2, 'ssh', 'target.example.test', 22) RETURNING id::text`, org, name+"-"+suffix)
		for _, u := range []string{external, operator} {
			exec(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
				VALUES ($1, $2, 'user', $3, '{view}')`, org, id, u)
		}
		return id
	}
	opened, closed := entry("cl-open"), entry("cl-closed")
	exec(`INSERT INTO vendor_org_targets (org_id, vendor_org_id, target_type, target_id) VALUES ($1, $2, 'pam_entry', $3)`, org, vendor, opened)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	file := func(userID, resourceType, resourceID string) (int, map[string]interface{}) {
		t.Helper()
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
			c.Set("user_id", userID)
			c.Set("roles", []string{"user"})
			c.Next()
		})
		r.POST("/requests", s.handleCreateAccessRequest)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/requests", strings.NewReader(fmt.Sprintf(
			`{"resource_type":%q,"resource_id":%q,"resource_name":"target","justification":"patch window","duration":"4h"}`,
			resourceType, resourceID)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	if code, body := file(external, "pam_entry", opened); code != http.StatusCreated {
		t.Errorf("an external user asks for an entry open to their vendor: %d %v, want 201", code, body)
	}
	if code, body := file(external, "pam_entry", closed); code != http.StatusForbidden || body["code"] != "external_target_not_open" {
		t.Errorf("an external user asks for an entry not open to their vendor: %d %v, want 403 external_target_not_open", code, body)
	}
	if n := scalar(`SELECT count(*)::text FROM access_requests WHERE requester_id = $1 AND resource_id = $2::uuid`, external, closed); n != "0" {
		t.Errorf("the refused request left %s rows", n)
	}
	if code, body := file(operator, "pam_entry", closed); code != http.StatusCreated {
		t.Errorf("an internal user asks for the same entry: %d %v, want 201", code, body)
	}

	if code, body := file(external, "vault_credential", "00000000-0000-0000-0000-0000000000aa"); code != http.StatusForbidden || body["code"] != "external_reveal_forbidden" {
		t.Errorf("an external user asks for a vault credential: %d %v, want 403 external_reveal_forbidden", code, body)
	}
	if code, body := file(operator, "vault_credential", "00000000-0000-0000-0000-0000000000aa"); body["code"] == "external_reveal_forbidden" {
		t.Errorf("an internal user's vault credential request was refused as an external user's: %d %v", code, body)
	}

	exec(`UPDATE vendor_organizations SET closed_list = false WHERE id = $1`, vendor)
	if code, body := file(external, "pam_entry", closed); code != http.StatusCreated {
		t.Errorf("with the list off, an external user asks for the entry: %d %v, want 201", code, body)
	}
}
