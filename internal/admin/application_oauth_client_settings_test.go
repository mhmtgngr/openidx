package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// The console's Applications editor showed a "Require PKCE" box for every
// application and sent pkce_required on save. Nothing read it — the
// applications GET and list never returned it, so the box always showed its
// default — and nothing wrote it: UpdateApplication's allowlist ignored the
// key and the sync to the backing OAuth client did not carry it. A control
// that displays without enforcing, in the routing-layer family this
// repository keeps finding. The back-channel logout URI (backchannel_logout.go)
// had no console field at all. Both now come from, and go to, the
// oauth_clients row the OAuth flow enforces, joined on client_id within the
// tenant.

type appClientSettingsFixture struct {
	s          *Service
	orgA, orgB string
	appA, appB string
	tile       string // an application tile with no OAuth client behind it
}

func setupAppClientSettings(t *testing.T) (*appClientSettingsFixture, func()) {
	t.Helper()
	db, cleanup := setupPAMTestDB(t) // skips if no database is reachable
	if db == nil {
		return nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	seed := orgctx.WithBypassRLS(context.Background())
	f := &appClientSettingsFixture{
		s:    &Service{db: db, logger: zap.NewNop()},
		orgA: "00000000-0000-0000-0000-0000000000c1",
		orgB: "00000000-0000-0000-0000-0000000000c2",
		appA: "22222222-0000-0000-0000-0000000000c1",
		appB: "22222222-0000-0000-0000-0000000000c2",
		tile: "22222222-0000-0000-0000-0000000000c3",
	}
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seed, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org A (cs)', 'org-a-cs')`, f.orgA)
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1, 'Org B (cs)', 'org-b-cs')`, f.orgB)
	// client_id is globally unique in both tables, so the second tenant gets
	// its own; the join is still written tenant-scoped, as every read here is.
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, org_id) VALUES ($1, 'cs-client', 'Grafana', 'web', true, $2)`, f.appA, f.orgA)
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, org_id) VALUES ($1, 'cs-client-b', 'Grafana B', 'web', true, $2)`, f.appB, f.orgB)
	exec(`INSERT INTO applications (id, client_id, name, type, enabled, org_id) VALUES ($1, 'proxy-app-route-1', 'Intranet', 'web', true, $2)`, f.tile, f.orgA)
	exec(`INSERT INTO oauth_clients (id, client_id, name, type, pkce_required, back_channel_logout_uri, org_id)
	      VALUES (gen_random_uuid(), 'cs-client', 'Grafana', 'confidential', false, 'https://grafana.example/bcl', $1)`, f.orgA)
	exec(`INSERT INTO oauth_clients (id, client_id, name, type, pkce_required, back_channel_logout_uri, org_id)
	      VALUES (gen_random_uuid(), 'cs-client-b', 'Grafana B', 'confidential', true, 'https://b.example/bcl', $1)`, f.orgB)
	return f, cleanup
}

func (f *appClientSettingsFixture) clientRow(t *testing.T, clientID string) (pkce bool, uri *string) {
	t.Helper()
	if err := f.s.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()),
		`SELECT pkce_required, back_channel_logout_uri FROM oauth_clients WHERE client_id = $1`, clientID).
		Scan(&pkce, &uri); err != nil {
		t.Fatalf("client row: %v", err)
	}
	return pkce, uri
}

func (f *appClientSettingsFixture) getApp(t *testing.T, org, id string) Application {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/applications/"+id, nil).
		WithContext(orgctx.With(context.Background(), orgctx.Org{ID: org}))
	c.Params = gin.Params{{Key: "id", Value: id}}
	f.s.handleGetApplication(c)
	if w.Code != http.StatusOK {
		t.Fatalf("get application: %d %s", w.Code, w.Body.String())
	}
	var app Application
	if err := json.Unmarshal(w.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}
	return app
}

// The read path reports the backing client's settings, from the tenant's own
// client row, and omits them for a tile with no client behind it.
func TestApplicationReadsPKCEAndLogoutURIFromTheBackingClient(t *testing.T) {
	f, cleanup := setupAppClientSettings(t)
	if f == nil {
		return
	}
	defer cleanup()

	app := f.getApp(t, f.orgA, f.appA)
	if app.PKCERequired == nil || *app.PKCERequired != false || app.BackChannelLogoutURI == nil || *app.BackChannelLogoutURI != "https://grafana.example/bcl" {
		t.Fatalf("org A detail: pkce=%v uri=%v, want false / grafana", app.PKCERequired, app.BackChannelLogoutURI)
	}
	appB := f.getApp(t, f.orgB, f.appB)
	if appB.PKCERequired == nil || *appB.PKCERequired != true || appB.BackChannelLogoutURI == nil || *appB.BackChannelLogoutURI != "https://b.example/bcl" {
		t.Fatalf("org B detail must come from org B's client row: pkce=%v uri=%v", appB.PKCERequired, appB.BackChannelLogoutURI)
	}
	tile := f.getApp(t, f.orgA, f.tile)
	if tile.PKCERequired != nil || tile.BackChannelLogoutURI != nil {
		t.Fatalf("a tile with no OAuth client must omit both: pkce=%v uri=%v", tile.PKCERequired, tile.BackChannelLogoutURI)
	}

	// The list carries the same values, and the JSON omits the keys for the tile.
	apps, _, err := f.s.ListApplications(orgctx.With(context.Background(), orgctx.Org{ID: f.orgA}), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]Application{}
	for _, a := range apps {
		seen[a.ID] = a
	}
	if a := seen[f.appA]; a.PKCERequired == nil || *a.PKCERequired || a.BackChannelLogoutURI == nil {
		t.Fatalf("list: %+v", a)
	}
	raw, _ := json.Marshal(seen[f.tile])
	if strings.Contains(string(raw), "pkce_required") || strings.Contains(string(raw), "back_channel_logout_uri") {
		t.Fatalf("tile JSON must omit the keys: %s", raw)
	}
}

// The write path lands on the tenant's client row, and only there; an edit
// that names neither field leaves both alone.
func TestUpdateApplicationWritesPKCEAndLogoutURIToTheBackingClient(t *testing.T) {
	f, cleanup := setupAppClientSettings(t)
	if f == nil {
		return
	}
	defer cleanup()
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: f.orgA})

	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{
		"pkce_required":           true,
		"back_channel_logout_uri": "https://grafana.example/bcl-v2",
	}); err != nil {
		t.Fatal(err)
	}
	if pkce, uri := f.clientRow(t, "cs-client"); !pkce || uri == nil || *uri != "https://grafana.example/bcl-v2" {
		t.Fatalf("org A client after update: pkce=%v uri=%v", pkce, uri)
	}
	if pkce, uri := f.clientRow(t, "cs-client-b"); !pkce || uri == nil || *uri != "https://b.example/bcl" {
		t.Fatalf("org B's client must be untouched: pkce=%v uri=%v", pkce, uri)
	}

	// Clearing the URI persists as NULL; an unrelated edit leaves both alone.
	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{"back_channel_logout_uri": ""}); err != nil {
		t.Fatal(err)
	}
	if pkce, uri := f.clientRow(t, "cs-client"); !pkce || uri != nil {
		t.Fatalf("clearing: pkce=%v uri=%v, want true / nil", pkce, uri)
	}
	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{"description": "renamed"}); err != nil {
		t.Fatal(err)
	}
	if pkce, uri := f.clientRow(t, "cs-client"); !pkce || uri != nil {
		t.Fatalf("an edit naming neither field must not disturb them: pkce=%v uri=%v", pkce, uri)
	}
	// Only-client fields are a valid update on their own.
	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{"pkce_required": false}); err != nil {
		t.Fatalf("a client-only update must be accepted: %v", err)
	}
	if pkce, _ := f.clientRow(t, "cs-client"); pkce {
		t.Fatal("pkce_required=false did not land")
	}
}

// A URI the OAuth store would refuse is refused here too, before anything is
// written, and the handler answers 400.
func TestUpdateApplicationRefusesAnInsecureLogoutURI(t *testing.T) {
	f, cleanup := setupAppClientSettings(t)
	if f == nil {
		return
	}
	defer cleanup()
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: f.orgA})

	err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{
		"name":                    "Should Not Land",
		"back_channel_logout_uri": "http://grafana.example/bcl",
	})
	if !errors.Is(err, ErrInvalidBackChannelLogoutURI) {
		t.Fatalf("want ErrInvalidBackChannelLogoutURI, got %v", err)
	}
	if _, uri := f.clientRow(t, "cs-client"); uri == nil || *uri != "https://grafana.example/bcl" {
		t.Fatalf("a refused update must write nothing to the client: %v", uri)
	}
	var name string
	_ = f.s.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()), `SELECT name FROM applications WHERE id = $1`, f.appA).Scan(&name)
	if name != "Grafana" {
		t.Fatalf("a refused update must write nothing to the application either: name=%q", name)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/applications/"+f.appA,
		strings.NewReader(`{"back_channel_logout_uri":"http://grafana.example/bcl"}`)).WithContext(ctxA)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: f.appA}}
	f.s.handleUpdateApplication(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("handler: want 400, got %d %s", w.Code, w.Body.String())
	}
}

// The RP-Initiated Logout allowlist (oauth_clients.post_logout_redirect_uris)
// was reachable only through dynamic client registration. An installation
// driven by the console could never leave the origin fallback the OAuth
// service falls back to — and the OAuth service logs advice to "register
// post_logout_redirect_uris to tighten it", advice the shipped UI could not
// take. Advice that cannot be followed is the same defect family as a control
// that displays without enforcing, read from the other end.

func (f *appClientSettingsFixture) postLogoutRow(t *testing.T, clientID string) *string {
	t.Helper()
	var raw *string
	if err := f.s.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()),
		`SELECT post_logout_redirect_uris::text FROM oauth_clients WHERE client_id = $1`, clientID).
		Scan(&raw); err != nil {
		t.Fatalf("post-logout row: %v", err)
	}
	return raw
}

// The write path lands on the tenant's client row, clearing it goes back to
// SQL NULL, and an edit that does not name the key leaves the list alone.
func TestUpdateApplicationWritesThePostLogoutAllowlist(t *testing.T) {
	f, cleanup := setupAppClientSettings(t)
	if f == nil {
		return
	}
	defer cleanup()
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: f.orgA})

	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{
		"post_logout_redirect_uris": []interface{}{"https://grafana.example/bye", "https://grafana.example/signed-out?from=idp"},
	}); err != nil {
		t.Fatalf("a client-only update naming the allowlist must be accepted: %v", err)
	}
	raw := f.postLogoutRow(t, "cs-client")
	if raw == nil || !strings.Contains(*raw, "grafana.example/bye") || !strings.Contains(*raw, "from=idp") {
		t.Fatalf("allowlist did not land: %v", raw)
	}
	if other := f.postLogoutRow(t, "cs-client-b"); other != nil {
		t.Fatalf("org B's client must be untouched: %v", other)
	}

	// An edit naming other fields leaves the list where it is: a rename must
	// never widen a client back to the origin fallback.
	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{"description": "renamed"}); err != nil {
		t.Fatal(err)
	}
	if raw := f.postLogoutRow(t, "cs-client"); raw == nil || !strings.Contains(*raw, "grafana.example/bye") {
		t.Fatalf("an unrelated edit cleared the allowlist: %v", raw)
	}

	// Present and empty is how an operator deliberately goes back to the
	// fallback, and it is stored as NULL, the same spelling the OAuth client
	// store writes.
	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{
		"post_logout_redirect_uris": []interface{}{},
	}); err != nil {
		t.Fatal(err)
	}
	if raw := f.postLogoutRow(t, "cs-client"); raw != nil {
		t.Fatalf("clearing must store SQL NULL, got %q", *raw)
	}
}

// The console sends one URI per textarea line, so a trailing newline arrives
// as a blank entry. A blank entry could never be matched, so registering it
// would be refused and an ordinary edit would fail; it is dropped instead.
func TestUpdateApplicationDropsBlankAllowlistLines(t *testing.T) {
	f, cleanup := setupAppClientSettings(t)
	if f == nil {
		return
	}
	defer cleanup()
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: f.orgA})

	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{
		"post_logout_redirect_uris": []interface{}{" https://grafana.example/bye ", "", "   "},
	}); err != nil {
		t.Fatalf("blank lines must not fail the edit: %v", err)
	}
	raw := f.postLogoutRow(t, "cs-client")
	if raw == nil {
		t.Fatal("the one real entry did not land")
	}
	var stored []string
	if err := json.Unmarshal([]byte(*raw), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0] != "https://grafana.example/bye" {
		t.Fatalf("want exactly the trimmed entry, got %#v", stored)
	}
}

// A value the logout matcher could never equal is refused before anything is
// written, and the handler answers 400 rather than 500.
func TestUpdateApplicationRefusesAnUnmatchableAllowlistEntry(t *testing.T) {
	f, cleanup := setupAppClientSettings(t)
	if f == nil {
		return
	}
	defer cleanup()
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: f.orgA})

	err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{
		"name":                      "Should Not Land",
		"post_logout_redirect_uris": []interface{}{"/relative/path"},
	})
	if !errors.Is(err, ErrInvalidPostLogoutRedirectURIs) {
		t.Fatalf("want ErrInvalidPostLogoutRedirectURIs, got %v", err)
	}
	if raw := f.postLogoutRow(t, "cs-client"); raw != nil {
		t.Fatalf("a refused update must write nothing to the client: %v", raw)
	}
	var name string
	_ = f.s.db.Pool.QueryRow(orgctx.WithBypassRLS(context.Background()), `SELECT name FROM applications WHERE id = $1`, f.appA).Scan(&name)
	if name != "Grafana" {
		t.Fatalf("a refused update must write nothing to the application either: name=%q", name)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/applications/"+f.appA,
		strings.NewReader(`{"post_logout_redirect_uris":["/relative/path"]}`)).WithContext(ctxA)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: f.appA}}
	f.s.handleUpdateApplication(c)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("handler: want 400, got %d %s", w.Code, w.Body.String())
	}
}

// The read path tells the three states apart: a registered list, a client that
// registered nothing (an EMPTY ARRAY, not an omitted key — that client is the
// one still on the origin fallback and the console must show it the field),
// and a tile with no OAuth client behind it at all (key omitted).
func TestApplicationReadDistinguishesNoClientFromNoRegistration(t *testing.T) {
	f, cleanup := setupAppClientSettings(t)
	if f == nil {
		return
	}
	defer cleanup()
	ctxA := orgctx.With(context.Background(), orgctx.Org{ID: f.orgA})

	// Before any registration: the client exists, so the key is present and empty.
	app := f.getApp(t, f.orgA, f.appA)
	if app.PostLogoutRedirectURIs == nil {
		t.Fatal("a client that registered nothing must still carry the key, so the console shows an empty field")
	}
	if len(*app.PostLogoutRedirectURIs) != 0 {
		t.Fatalf("want an empty list, got %#v", *app.PostLogoutRedirectURIs)
	}
	raw, _ := json.Marshal(app)
	if !strings.Contains(string(raw), `"post_logout_redirect_uris":[]`) {
		t.Fatalf("the empty list must survive JSON as []: %s", raw)
	}

	// A tile with no OAuth client omits the key entirely.
	tile := f.getApp(t, f.orgA, f.tile)
	if tile.PostLogoutRedirectURIs != nil {
		t.Fatalf("a tile with no OAuth client must omit the key: %#v", *tile.PostLogoutRedirectURIs)
	}
	tileRaw, _ := json.Marshal(tile)
	if strings.Contains(string(tileRaw), "post_logout_redirect_uris") {
		t.Fatalf("tile JSON must omit the key: %s", tileRaw)
	}

	// After a registration, both the detail and the list report it.
	if err := f.s.UpdateApplication(ctxA, f.appA, map[string]interface{}{
		"post_logout_redirect_uris": []interface{}{"https://grafana.example/bye"},
	}); err != nil {
		t.Fatal(err)
	}
	app = f.getApp(t, f.orgA, f.appA)
	if app.PostLogoutRedirectURIs == nil || len(*app.PostLogoutRedirectURIs) != 1 ||
		(*app.PostLogoutRedirectURIs)[0] != "https://grafana.example/bye" {
		t.Fatalf("detail read: %#v", app.PostLogoutRedirectURIs)
	}
	apps, _, err := f.s.ListApplications(ctxA, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var found *Application
	for i := range apps {
		if apps[i].ID == f.appA {
			found = &apps[i]
		}
	}
	if found == nil || found.PostLogoutRedirectURIs == nil || len(*found.PostLogoutRedirectURIs) != 1 {
		t.Fatalf("list read: %+v", found)
	}

	// The other tenant reads its own client's registration, not this one's.
	appB := f.getApp(t, f.orgB, f.appB)
	if appB.PostLogoutRedirectURIs == nil || len(*appB.PostLogoutRedirectURIs) != 0 {
		t.Fatalf("org B must read its own row: %#v", appB.PostLogoutRedirectURIs)
	}
}
