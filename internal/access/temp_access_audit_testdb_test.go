package access

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

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Temporary access links are retired. On the migrated schema, through the
// real handlers: opening any link -- live, expired or never issued -- gets the
// 410 retirement page and writes nothing; revoking a link from its history
// still lands temp_access.revoked with the administrator as actor in the
// issuing tenant's unified trail. The other tenant's trail carries none of it,
// and its administrator's query does not see it.
func TestARetiredLinkOpensNothingAndItsRevocationIsAudited(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}

	const orgA = "00000000-0000-0000-0000-000000000010" // seeded by migrations
	var orgB string
	if err := db.Pool.QueryRow(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('temp-access-audit-b', 'temp-access-audit-b') RETURNING id::text`).
		Scan(&orgB); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	seedUser := func(org, name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO users (username, email, enabled, org_id)
			VALUES ($1::varchar, $1::varchar || '@example.test', true, $2::uuid) RETURNING id::text`,
			name+"-"+suffix, org).Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	issuer := seedUser(orgA, "ta-issuer")
	admin := seedUser(orgA, "ta-admin")

	var entryID string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, username)
		VALUES ($1::uuid, $2, 'ssh', 'target.example.test', 22, 'vendor') RETURNING id::text`,
		orgA, "ta-target-"+suffix).Scan(&entryID); err != nil {
		t.Fatalf("seed entry: %v", err)
	}
	seedLink := func(token string, expiresIn string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `
			INSERT INTO temp_access_links (
				token, name, description, pam_entry_id, protocol, target_host, target_port, username,
				created_by, created_by_email, expires_at, max_uses, current_uses,
				allowed_ips, guacamole_connection_id, access_url, last_used_ip, status, org_id)
			VALUES ($1, $2, '', $3::uuid, 'ssh', 'target.example.test', 22, 'vendor',
				$4::uuid, 'issuer@example.test', NOW() + $5::interval, 0, 0,
				'{}', '', $7, '', 'active', $6::uuid)
			RETURNING id::text`, token, "link-"+token, entryID, issuer, expiresIn, orgA,
			"https://access.example.test/temp-access/"+token).Scan(&id); err != nil {
			t.Fatalf("seed link %s: %v", token, err)
		}
		return id
	}
	liveToken := "live-" + suffix
	expiredToken := "expired-" + suffix
	liveLink := seedLink(liveToken, "1 day")
	expiredLink := seedLink(expiredToken, "-1 hour")

	logger := zap.NewNop()
	svc := &Service{db: db, logger: logger, auditService: NewUnifiedAuditService(db, logger)}

	redeem := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		// A vendor's browser: no session, no organization on the context.
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/temp-access/"+token, nil)
		c.Request.Header.Set("User-Agent", "vendor-browser/1.0")
		c.Request.RemoteAddr = "203.0.113.7:51234"
		c.Params = append(c.Params, gin.Param{Key: "token", Value: token})
		svc.handleRetiredTempAccess(c)
		return w
	}
	type event struct {
		orgID   string
		userID  *string
		actorIP string
		details map[string]any
	}
	eventsOf := func(eventType, linkID string) []event {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `
			SELECT org_id::text, user_id::text, actor_ip, details
			  FROM unified_audit_events
			 WHERE event_type = $1 AND details->>'link_id' = $2
			 ORDER BY created_at`, eventType, linkID)
		if err != nil {
			t.Fatalf("read events: %v", err)
		}
		defer rows.Close()
		var out []event
		for rows.Next() {
			var e event
			var raw []byte
			if err := rows.Scan(&e.orgID, &e.userID, &e.actorIP, &raw); err != nil {
				t.Fatalf("scan event: %v", err)
			}
			_ = json.Unmarshal(raw, &e.details)
			out = append(out, e)
		}
		return out
	}
	tempEventsIn := func(org string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM unified_audit_events WHERE org_id = $1 AND event_type LIKE 'temp_access.%'`, org).Scan(&n); err != nil {
			t.Fatalf("count events: %v", err)
		}
		return n
	}

	// Links no longer redeem. A live link, an expired one and a token never
	// issued get the same 410 page, and none of them touches the link or the
	// trail: the page reads nothing, so it cannot tell a visitor which tokens
	// exist, and a stranger cannot write into the trail by guessing.
	before := tempEventsIn(orgA)
	for _, token := range []string{liveToken, expiredToken, "no-such-" + suffix} {
		w := redeem(token)
		if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "Retired") {
			t.Fatalf("opening %s: %d %s, want the 410 retirement page", token, w.Code, w.Body.String())
		}
	}
	if after := tempEventsIn(orgA); after != before {
		t.Errorf("opening retired links added %d rows to org A's trail", after-before)
	}
	var uses int
	if err := db.Pool.QueryRow(ctx, `SELECT current_uses FROM temp_access_links WHERE id = $1`, liveLink).Scan(&uses); err != nil || uses != 0 {
		t.Errorf("the live link's use count is %d (%v), want 0", uses, err)
	}
	_ = expiredLink

	// A revocation by an administrator of org A, through the handler.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/access/temp-access/"+liveLink, nil).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: orgA}))
	c.Set("user_id", admin)
	c.Set("roles", []string{"admin"})
	c.Params = append(c.Params, gin.Param{Key: "id", Value: liveLink})
	svc.handleRevokeTempAccess(c)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	revoked := eventsOf("temp_access.revoked", liveLink)
	if len(revoked) != 1 || revoked[0].userID == nil || *revoked[0].userID != admin || revoked[0].orgID != orgA {
		t.Errorf("temp_access.revoked rows: %+v, want one in org A with the administrator as actor", revoked)
	}
	// The other tenant's trail carries none of it, by column and by query.
	if n := tempEventsIn(orgB); n != 0 {
		t.Errorf("org B's trail carries %d temp access events", n)
	}
	res, err := svc.auditService.QueryEvents(orgctx.With(ctx, orgctx.Org{ID: orgB}),
		&AuditQueryFilters{EventTypes: []string{"temp_access.revoked"}, Limit: 50})
	if err != nil {
		t.Fatalf("query as org B: %v", err)
	}
	if len(res.Events) != 0 {
		t.Errorf("org B's administrator sees %d of org A's temp access events", len(res.Events))
	}
	res, err = svc.auditService.QueryEvents(orgctx.With(ctx, orgctx.Org{ID: orgA}),
		&AuditQueryFilters{EventTypes: []string{"temp_access.revoked"}, Limit: 50})
	if err != nil {
		t.Fatalf("query as org A: %v", err)
	}
	if len(res.Events) == 0 {
		t.Error("org A's administrator does not see the temp_access.revoked event on the Unified Audit query")
	}
}
