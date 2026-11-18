package access

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// Pins on the migrated schema: allocated once and kept, reused when freed,
// refused outside the pool, written into a service only while the organization
// asks the agent to answer names, and told to a device only for what it can
// dial.
func TestNamePinsOnTheMigratedSchema(t *testing.T) {
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
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})

	seed := func(client, name string, enabled bool, dns ...string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(ctx, `INSERT INTO applications (client_id, name, type, kind, org_id, enabled)
			VALUES ($1, $2, 'network', 'network', $3, $4) RETURNING id::text`, client, name, org, enabled).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		if _, err := db.Pool.Exec(ctx, `INSERT INTO network_targets (application_id, org_id, hosts, cidrs, dns_names, port_ranges, protocols)
			VALUES ($1, $2, '{}', '{}'::cidr[], $3::text[], '[{"low":443,"high":443}]', '{tcp}')`, id, org, dns); err != nil {
			t.Fatalf("seed target %s: %v", name, err)
		}
		return id
	}
	wiki := seed("pin-wiki", "Wiki", true, "wiki.corp.example")
	hr := seed("pin-hr", "HR", true, "hr.corp.example")
	multi := seed("pin-multi", "Two names", true, "a.corp.example", "b.corp.example")
	wild := seed("pin-wild", "Wildcard", true, "*.corp.example")
	off := seed("pin-off", "Retired", false, "old.corp.example")

	// ---- allocation ----
	p1, err := allocatePin(ctx, db, org, wiki)
	if err != nil || p1 != "100.127.0.10" {
		t.Fatalf("first pin = %q, %v; want 100.127.0.10", p1, err)
	}
	if again, _ := allocatePin(ctx, db, org, wiki); again != p1 {
		t.Errorf("a second allocation changed the pin: %s then %s", p1, again)
	}
	p2, err := allocatePin(ctx, db, org, hr)
	if err != nil || p2 != "100.127.0.11" {
		t.Fatalf("second pin = %q, %v; want 100.127.0.11", p2, err)
	}
	if _, err := allocatePin(ctx, db, org, "00000000-0000-0000-0000-00000000dead"); err == nil {
		t.Error("a pin was allocated for a resource with no target")
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE network_targets SET pin_ip = '10.0.0.1' WHERE application_id = $1`, multi); err == nil {
		t.Error("the database accepted a pin outside the pool")
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE network_targets SET pin_ip = $2::inet WHERE application_id = $1`, multi, p1); err == nil {
		t.Error("the database accepted the same pin twice in one organization")
	}

	// ---- the reconciler's view ----
	rec := &ZitiReconciler{db: db, logger: zap.NewNop(), status: map[string]string{}}
	pinsOf := func() map[string]string {
		t.Helper()
		got, err := rec.loadDesiredNetworkServices(ctx)
		if err != nil {
			t.Fatalf("load desired: %v", err)
		}
		out := map[string]string{}
		for _, d := range got {
			out[d.ApplicationID] = d.Target.PinIP
		}
		return out
	}
	got := pinsOf()
	if len(got) != 4 {
		t.Fatalf("desired services = %v, want the four enabled resources", got)
	}
	for id, pin := range got {
		if pin != "" {
			t.Errorf("%s carries the pin %s while the organization has not asked for agent name resolution", id, pin)
		}
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO org_network_policy (org_id, always_on, tunnel_scope, name_resolution)
		VALUES ($1, true, 'all', 'agent')`, org); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	got = pinsOf()
	if got[wiki] != p1 || got[hr] != p2 {
		t.Errorf("pins = wiki %q hr %q, want the stored %s and %s", got[wiki], got[hr], p1, p2)
	}
	if got[multi] != "" || got[wild] != "" {
		t.Errorf("a resource that cannot have a pin got one: multi %q wildcard %q", got[multi], got[wild])
	}
	if _, ok := got[off]; ok {
		t.Error("a disabled resource is desired")
	}
	if again := pinsOf(); !reflect.DeepEqual(again, got) {
		t.Errorf("the pins moved between two passes: %v then %v", got, again)
	}

	// A freed address is the next one handed out.
	if _, err := db.Pool.Exec(ctx, `DELETE FROM network_targets WHERE application_id = $1`, hr); err != nil {
		t.Fatal(err)
	}
	extra := seed("pin-extra", "Extra", true, "extra.corp.example")
	if pin, err := allocatePin(ctx, db, org, extra); err != nil || pin != p2 {
		t.Errorf("the freed address was not reused: %q, %v (want %s)", pin, err, p2)
	}
	hr = extra // hr's target is gone; the extra resource took its pin

	// ---- what a device is told ----
	var u1, u2 string
	for _, q := range []struct {
		dst        *string
		name, mail string
	}{{&u1, "pin-u1", "pin-u1@example.test"}, {&u2, "pin-u2", "pin-u2@example.test"}} {
		if err := db.Pool.QueryRow(ctx, `INSERT INTO users (username, email, org_id) VALUES ($1, $2, $3) RETURNING id::text`,
			q.name, q.mail, org).Scan(q.dst); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	for _, a := range []struct{ agent, user string }{{"agent-pin-1", u1}, {"agent-pin-2", u2}} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO enrolled_agents (agent_id, device_id, auth_token_hash, org_id, enrolled_by_user_id, status)
			VALUES ($1, $1, 'x', $2, $3, 'active')`, a.agent, org, a.user); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1, $2, $3)`, u1, wiki, org); err != nil {
		t.Fatalf("assign: %v", err)
	}

	names := func(pins []namePin) []string {
		var out []string
		for _, p := range pins {
			out = append(out, p.Name+"="+p.IP)
		}
		return out
	}
	// Assignment not enforced: every enrolled device may dial every network
	// service, so it is told every pin, in name order.
	all, err := loadDeviceNamePins(ctx, db, org, "agent-pin-2", false)
	if err != nil || !reflect.DeepEqual(names(all), []string{"extra.corp.example=" + p2, "wiki.corp.example=" + p1}) {
		t.Errorf("unenforced pins = %v, %v", names(all), err)
	}
	// Enforced: only what the enrolling person is assigned.
	one, err := loadDeviceNamePins(ctx, db, org, "agent-pin-1", true)
	if err != nil || !reflect.DeepEqual(names(one), []string{"wiki.corp.example=" + p1}) {
		t.Errorf("pins for the assigned person = %v, %v", names(one), err)
	}
	if none, err := loadDeviceNamePins(ctx, db, org, "agent-pin-2", true); err != nil || len(none) != 0 {
		t.Errorf("pins for a person with no assignment = %v, %v", names(none), err)
	}
	if none, err := loadDeviceNamePins(ctx, db, org, "no-such-agent", true); err != nil || len(none) != 0 {
		t.Errorf("pins for an unknown device = %v, %v", names(none), err)
	}
	_ = hr

	// ---- the policy a device receives ----
	pol, err := loadDeviceNetworkPolicy(ctx, db, org, "agent-pin-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if pol.NameResolution != nameResolutionAgent || len(pol.NamePins) != 1 || pol.NamePinsVersion == "" || !isPolicyVersion(pol.Version) {
		t.Fatalf("agent-mode policy = %+v", pol)
	}
	agentVersion := pol.Version
	other, _ := loadDeviceNetworkPolicy(ctx, db, org, "agent-pin-2", true)
	if other.Version != agentVersion || other.NamePinsVersion == pol.NamePinsVersion && len(other.NamePins) != len(pol.NamePins) {
		t.Errorf("the organization's version must not depend on the device: %s vs %s", other.Version, agentVersion)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE org_network_policy SET name_resolution = 'tunnel' WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}
	back, _ := loadDeviceNetworkPolicy(ctx, db, org, "agent-pin-1", true)
	if back.NameResolution != "" || len(back.NamePins) != 0 || back.NamePinsVersion != "" || back.Version == agentVersion {
		t.Errorf("tunnel-mode policy = %+v", back)
	}
	raw, _ := json.Marshal(back)
	for _, field := range []string{"name_resolution", "name_pins"} {
		if bytes.Contains(raw, []byte(field)) {
			t.Errorf("the tunnel-mode policy still carries %s: %s", field, raw)
		}
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE org_network_policy SET name_resolution = 'agent' WHERE org_id = $1`, org); err != nil {
		t.Fatal(err)
	}

	// ---- the administrator's API ----
	gin.SetMode(gin.TestMode)
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(orgctx.With(c.Request.Context(), orgctx.Org{ID: org}))
		c.Next()
	})
	api := r.Group("/api/v1/access")
	api.GET("/network-policy", svc.handleGetNetworkPolicy)
	api.PUT("/network-policy", svc.handlePutNetworkPolicy)
	api.GET("/resources/:id/network-target", svc.handleGetNetworkTarget)
	do := func(method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var out map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, v := do("GET", "/api/v1/access/network-policy", ""); code != http.StatusOK || v["name_resolution"] != "agent" {
		t.Errorf("GET policy = %d %v", code, v)
	}
	if code, _ := do("PUT", "/api/v1/access/network-policy", `{"name_resolution":"bogus"}`); code != http.StatusBadRequest {
		t.Errorf("an unknown name_resolution answered %d, want 400", code)
	}
	if code, v := do("PUT", "/api/v1/access/network-policy", `{"name_resolution":"tunnel"}`); code != http.StatusOK || v["name_resolution"] != "tunnel" {
		t.Errorf("PUT tunnel = %d %v", code, v)
	}
	// A save that does not mention it leaves it alone.
	if code, v := do("PUT", "/api/v1/access/network-policy", `{"split_tunnel":false}`); code != http.StatusOK || v["name_resolution"] != "tunnel" {
		t.Errorf("an unrelated save changed name_resolution: %d %v", code, v)
	}
	// The administrator sees the pin on the resource, read-only.
	code, v := do("GET", "/api/v1/access/resources/"+wiki+"/network-target", "")
	if tgt, _ := v["target"].(map[string]interface{}); code != http.StatusOK || tgt["pin_ip"] != p1 {
		t.Errorf("GET target = %d %v, want pin_ip %s", code, v, p1)
	}
}
