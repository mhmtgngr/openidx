package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// DARK PUBLISH on the migrated schema: one call writes the network resource, its
// assignments and its device-trust condition together, or writes nothing.

const (
	darkOrgA = "00000000-0000-0000-0000-000000000010"
	darkOrgB = "00000000-0000-0000-0000-0000000000d2"
	darkUser = "00000000-0000-0000-0000-0000000000d9"
)

type darkWorld struct {
	t          *testing.T
	db         *database.PostgresDB
	svc        *Service
	groupA1    string
	groupA2    string
	groupB     string
	userA      string
	userB      string
	ctxA, ctxB context.Context
}

func newDarkWorld(t *testing.T) *darkWorld {
	t.Helper()
	pinTargetGuard(t)
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	w := &darkWorld{t: t, db: db,
		svc:  &Service{db: db, config: &config.Config{}, logger: zap.NewNop()},
		ctxA: orgctx.With(bg, orgctx.Org{ID: darkOrgA}),
		ctxB: orgctx.With(bg, orgctx.Org{ID: darkOrgB}),
	}
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	w.exec(`INSERT INTO organizations (id, name, slug) VALUES ($1::uuid, $2, $2)`, darkOrgB, "dark-b-"+sfx)
	w.groupA1 = w.scalar(`INSERT INTO groups (name, org_id) VALUES ($1, $2::uuid) RETURNING id::text`, "eng-"+sfx, darkOrgA)
	w.groupA2 = w.scalar(`INSERT INTO groups (name, org_id) VALUES ($1, $2::uuid) RETURNING id::text`, "ops-"+sfx, darkOrgA)
	w.groupB = w.scalar(`INSERT INTO groups (name, org_id) VALUES ($1, $2::uuid) RETURNING id::text`, "other-"+sfx, darkOrgB)
	w.userA = w.scalar(`INSERT INTO users (username, email, first_name, last_name, enabled, org_id)
		VALUES ($1, $2, 'A', 'User', true, $3::uuid) RETURNING id::text`, "dark-a-"+sfx, "dark-a-"+sfx+"@corp.example", darkOrgA)
	w.userB = w.scalar(`INSERT INTO users (username, email, first_name, last_name, enabled, org_id)
		VALUES ($1, $2, 'B', 'User', true, $3::uuid) RETURNING id::text`, "dark-b-"+sfx, "dark-b-"+sfx+"@corp.example", darkOrgB)
	return w
}

func (w *darkWorld) exec(q string, args ...interface{}) {
	w.t.Helper()
	if _, err := w.db.Pool.Exec(context.Background(), q, args...); err != nil {
		w.t.Fatalf("%s: %v", q, err)
	}
}

func (w *darkWorld) scalar(q string, args ...interface{}) string {
	w.t.Helper()
	var s string
	if err := w.db.Pool.QueryRow(context.Background(), q, args...).Scan(&s); err != nil {
		w.t.Fatalf("%s: %v", q, err)
	}
	return s
}

func (w *darkWorld) count(q string, args ...interface{}) int {
	w.t.Helper()
	var n int
	if err := w.db.Pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		w.t.Fatalf("%s: %v", q, err)
	}
	return n
}

// nothingLeft asserts that a refused publish left no row behind in any table it writes.
func (w *darkWorld) nothingLeft(before darkCounts) {
	w.t.Helper()
	if got := w.counts(); got != before {
		w.t.Errorf("a refused publish left rows behind: before %+v, after %+v", before, got)
	}
}

type darkCounts struct{ apps, targets, groupAssign, userAssign, conditions int }

func (w *darkWorld) counts() darkCounts {
	return darkCounts{
		apps:        w.count(`SELECT count(*) FROM applications WHERE kind = 'network'`),
		targets:     w.count(`SELECT count(*) FROM network_targets`),
		groupAssign: w.count(`SELECT count(*) FROM group_application_assignments`),
		userAssign:  w.count(`SELECT count(*) FROM user_application_assignments`),
		conditions:  w.count(`SELECT count(*) FROM resource_conditions`),
	}
}

func (w *darkWorld) publish(ctx context.Context, org string, req publishRequest) (*publishResult, error) {
	return w.svc.publishDarkApp(ctx, org, darkUser, req)
}

func TestPublishDarkAppWritesEverythingOrNothing(t *testing.T) {
	w := newDarkWorld(t)
	res, err := w.publish(w.ctxA, darkOrgA, publishRequest{
		Name: "Wiki", Address: "https://wiki.corp.example/docs",
		GroupIDs: []string{w.groupA1}, UserIDs: []string{w.userA},
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if res.ServiceName != "openidx-net-"+res.ID || res.URL != "https://wiki.corp.example/docs" || res.Groups != 1 || res.Users != 1 || !res.RequireTrustedDevice {
		t.Errorf("result = %+v", res)
	}
	var kind, typ, baseURL string
	var enabled, requireAssignment bool
	if err := w.db.Pool.QueryRow(context.Background(),
		`SELECT kind, type, COALESCE(base_url,''), enabled, COALESCE(require_assignment,false) FROM applications WHERE id = $1::uuid`, res.ID).
		Scan(&kind, &typ, &baseURL, &enabled, &requireAssignment); err != nil {
		t.Fatal(err)
	}
	if kind != "network" || typ != "network" || baseURL != "https://wiki.corp.example/docs" || !enabled || !requireAssignment {
		t.Errorf("application: kind=%s type=%s base_url=%q enabled=%v require_assignment=%v", kind, typ, baseURL, enabled, requireAssignment)
	}
	if got := w.scalar(`SELECT array_to_string(dns_names, ',')||'|'||array_to_string(hosts, ',')||'|'||array_to_string(cidrs::text[], ',')||'|'||port_ranges::text||'|'||array_to_string(protocols, ',')||'|'||COALESCE(forward_address,'')
		FROM network_targets WHERE application_id = $1::uuid`, res.ID); got != `wiki.corp.example|||[{"low": 443, "high": 443}]|tcp|` {
		t.Errorf("network target = %q", got)
	}
	if n := w.count(`SELECT count(*) FROM group_application_assignments WHERE application_id = $1::uuid AND group_id = $2::uuid AND org_id = $3::uuid`, res.ID, w.groupA1, darkOrgA); n != 1 {
		t.Errorf("group assignments = %d, want 1", n)
	}
	if n := w.count(`SELECT count(*) FROM user_application_assignments WHERE application_id = $1::uuid AND user_id = $2::uuid AND org_id = $3::uuid`, res.ID, w.userA, darkOrgA); n != 1 {
		t.Errorf("user assignments = %d, want 1", n)
	}
	if got := w.scalar(`SELECT require_device_trust::text||'|'||COALESCE(updated_by::text,'') FROM resource_conditions WHERE application_id = $1::uuid`, res.ID); got != "true|"+darkUser {
		t.Errorf("condition = %q, want trusted device required, updated by the actor", got)
	}
}

func TestPublishDarkAppTrustedDeviceCanBeTurnedOff(t *testing.T) {
	w := newDarkWorld(t)
	off := false
	res, err := w.publish(w.ctxA, darkOrgA, publishRequest{Name: "Open wiki", Address: "wiki2.corp.example", GroupIDs: []string{w.groupA1}, RequireTrustedDevice: &off})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if res.RequireTrustedDevice {
		t.Error("the result says a trusted device is required")
	}
	if got := w.scalar(`SELECT require_device_trust::text FROM resource_conditions WHERE application_id = $1::uuid`, res.ID); got != "false" {
		t.Errorf("require_device_trust = %s, want false", got)
	}
}

func TestPublishDarkAppRefusesWhatItCannotWriteWhole(t *testing.T) {
	w := newDarkWorld(t)
	before := w.counts()
	good := publishRequest{Name: "Wiki", Address: "https://wiki.corp.example", GroupIDs: []string{w.groupA1}}

	cases := []struct {
		name string
		mut  func(*publishRequest)
		want error
	}{
		{"no assignee", func(r *publishRequest) { r.GroupIDs = nil }, errPublishNoAssignee},
		{"a group of another organization", func(r *publishRequest) { r.GroupIDs = []string{w.groupA1, w.groupB} }, errPublishUnknownPrincipal},
		{"a user of another organization", func(r *publishRequest) { r.UserIDs = []string{w.userB} }, errPublishUnknownPrincipal},
		{"a group that does not exist", func(r *publishRequest) { r.GroupIDs = []string{uuid.NewString()} }, errPublishUnknownPrincipal},
		{"an id that is not an id", func(r *publishRequest) { r.GroupIDs = []string{"not-a-uuid"} }, errPublishUnknownPrincipal},
		{"a bad address", func(r *publishRequest) { r.Address = "ftp://files.corp.example" }, errPublishAddress},
		{"no name", func(r *publishRequest) { r.Name = "   " }, errPublishName},
		{"an unknown site", func(r *publishRequest) { r.Site = "no-such-site" }, errUnknownSite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := good
			tc.mut(&req)
			if _, err := w.publish(w.ctxA, darkOrgA, req); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			w.nothingLeft(before)
		})
	}
}

func TestPublishDarkAppRefusesThePlatformAddress(t *testing.T) {
	w := newDarkWorld(t)
	withPlatformHosts(t, "https://ctrl.corp.example:1280")
	before := w.counts()
	_, err := w.publish(w.ctxA, darkOrgA, publishRequest{Name: "Controller", Address: "https://ctrl.corp.example:1280", GroupIDs: []string{w.groupA1}})
	if err == nil {
		t.Fatal("the controller's own address was published")
	}
	if errors.Is(err, errPublishAddress) || errors.Is(err, errPublishDuplicate) {
		t.Errorf("the guard's refusal was reported as %v; it is its own error", err)
	}
	w.nothingLeft(before)
}

func TestPublishDarkAppRefusesADuplicateNameAndPort(t *testing.T) {
	w := newDarkWorld(t)
	first := publishRequest{Name: "Wiki", Address: "https://wiki.corp.example", GroupIDs: []string{w.groupA1}}
	if _, err := w.publish(w.ctxA, darkOrgA, first); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	before := w.counts()
	second := first
	second.Name = "Wiki again"
	second.GroupIDs = []string{w.groupA2}
	if _, err := w.publish(w.ctxA, darkOrgA, second); !errors.Is(err, errPublishDuplicate) {
		t.Fatalf("second publish of the same name and port: err = %v, want errPublishDuplicate", err)
	}
	w.nothingLeft(before)

	other := first
	other.Name = "Wiki on 8443"
	other.Address = "https://wiki.corp.example:8443"
	if _, err := w.publish(w.ctxA, darkOrgA, other); err != nil {
		t.Errorf("the same name on another port was refused: %v", err)
	}
	b := publishRequest{Name: "Wiki of B", Address: "https://wiki.corp.example", GroupIDs: []string{w.groupB}}
	if _, err := w.publish(w.ctxB, darkOrgB, b); err != nil {
		t.Errorf("another organization publishing the same name was refused: %v", err)
	}
}

func TestPublishDarkAppReportsWhatTheInstallEnforces(t *testing.T) {
	w := newDarkWorld(t)
	req := publishRequest{Name: "Wiki", Address: "https://wiki.corp.example", GroupIDs: []string{w.groupA1}}

	res, err := w.publish(w.ctxA, darkOrgA, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Enforcement.Assignment || res.Enforcement.DeviceTrust != "off" {
		t.Errorf("a default install reports %+v, want assignment=false device_trust=off", res.Enforcement)
	}

	w.svc.config = &config.Config{AccessAssignmentEnforce: true, PostureDeviceTrustGate: " Enforce "}
	req.Name, req.Address = "Wiki 2", "https://wiki2.corp.example"
	res, err = w.publish(w.ctxA, darkOrgA, req)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Enforcement.Assignment || res.Enforcement.DeviceTrust != "enforce" {
		t.Errorf("an enforcing install reports %+v, want assignment=true device_trust=enforce", res.Enforcement)
	}
}

func TestPublishDarkAppHandler(t *testing.T) {
	w := newDarkWorld(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: darkOrgA}))
		c.Set("user_id", darkUser)
		c.Next()
	})
	r.POST("/api/v1/access/network-resources/publish", w.svc.handlePublishDarkApp)

	post := func(body map[string]interface{}) (int, map[string]interface{}) {
		raw, _ := json.Marshal(body)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/access/network-resources/publish", bytes.NewReader(raw)))
		out := map[string]interface{}{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, body := post(map[string]interface{}{"name": "Wiki", "address": "https://wiki.corp.example", "group_ids": []string{w.groupA1}})
	if code != http.StatusCreated {
		t.Fatalf("publish: %d %v", code, body)
	}
	for _, k := range []string{"id", "name", "service_name", "url", "target", "groups", "users", "require_trusted_device", "enforcement"} {
		if _, ok := body[k]; !ok {
			t.Errorf("201 body has no %q: %v", k, body)
		}
	}
	code, body = post(map[string]interface{}{"name": "Wiki", "address": "https://wiki.corp.example", "group_ids": []string{w.groupA2}})
	if code != http.StatusConflict || body["code"] != "already_published" {
		t.Errorf("duplicate: %d %v, want 409 already_published", code, body)
	}
	code, body = post(map[string]interface{}{"name": "Bad", "address": "ftp://x.corp.example", "group_ids": []string{w.groupA1}})
	if code != http.StatusBadRequest || body["code"] != "invalid_address" {
		t.Errorf("bad address: %d %v, want 400 invalid_address", code, body)
	}
	code, body = post(map[string]interface{}{"name": "Nobody", "address": "https://nobody.corp.example"})
	if code != http.StatusBadRequest || body["code"] != "assignee_required" {
		t.Errorf("no assignee: %d %v, want 400 assignee_required", code, body)
	}
	code, body = post(map[string]interface{}{"name": "Foreign", "address": "https://foreign.corp.example", "group_ids": []string{w.groupB}})
	if code != http.StatusBadRequest || body["code"] != "unknown_group" {
		t.Errorf("another organization's group: %d %v, want 400 unknown_group", code, body)
	}
	code, body = post(map[string]interface{}{"name": "Foreign user", "address": "https://foreign2.corp.example", "group_ids": []string{w.groupA1}, "user_ids": []string{w.userB}})
	if code != http.StatusBadRequest || body["code"] != "unknown_user" {
		t.Errorf("another organization's user: %d %v, want 400 unknown_user", code, body)
	}
}
