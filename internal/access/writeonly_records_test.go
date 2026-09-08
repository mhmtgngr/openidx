package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// Two records that were written and never read.
//
// The silent-write census recorded both rather than waiving them quietly: no
// query in the product selected proxy_sessions.idp_id, and no query selected
// from edr_device_mappings at all. A value nothing reads cannot be wrong, which
// is why neither had ever been noticed going missing -- and it is also why
// neither was worth writing.
//
// Both now have a reader, so both writes matter, and these tests hold the read
// to the question it exists to answer. Not "does the column round-trip" -- that
// would pass on a column nobody consults -- but the operator's question: which
// provider authenticated this live session, and which device caused this
// posture failure.

const writeOnlySchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255), enabled BOOLEAN DEFAULT true, org_id UUID);
CREATE TABLE IF NOT EXISTS proxy_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID, route_id UUID, session_token TEXT,
    ip_address VARCHAR(64) DEFAULT '', user_agent TEXT DEFAULT '',
    idp_id UUID, revoked BOOLEAN DEFAULT false,
    started_at TIMESTAMPTZ DEFAULT NOW(), last_active_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '1 hour', org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255), org_id UUID);
CREATE TABLE IF NOT EXISTS edr_posture_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID, name VARCHAR(255) NOT NULL,
    provider VARCHAR(32) NOT NULL, base_url TEXT, client_id TEXT, client_secret_enc TEXT,
    tenant_id TEXT, api_user TEXT, api_token_enc TEXT, posture_check_id UUID,
    match_strategy VARCHAR(16) NOT NULL DEFAULT 'serial', result_ttl_minutes INTEGER NOT NULL DEFAULT 60,
    poll_interval_minutes INTEGER NOT NULL DEFAULT 15, enabled BOOLEAN NOT NULL DEFAULT true,
    last_sync_at TIMESTAMPTZ, last_sync_status VARCHAR(32), last_sync_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS edr_device_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), org_id UUID,
    source_id UUID NOT NULL REFERENCES edr_posture_sources(id) ON DELETE CASCADE,
    external_device_id VARCHAR(255) NOT NULL, match_value VARCHAR(255), user_id UUID,
    identity_id UUID, last_compliant BOOLEAN, last_risk VARCHAR(32), last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_id, external_device_id));`

const (
	woOrg      = "00000000-0000-0000-0000-0000000000a1"
	woOtherOrg = "00000000-0000-0000-0000-0000000000a2"
	woIDP      = "00000000-0000-0000-0000-0000000000a3"
	woSource   = "00000000-0000-0000-0000-0000000000a4"
	woIdentity = "00000000-0000-0000-0000-0000000000a5"
)

func writeOnlyFixture(t *testing.T) (*Service, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: woOrg})

	if _, err := db.Pool.Exec(ctx, writeOnlySchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO identity_providers (id, name, org_id) VALUES ($1::uuid, 'Contoso Entra', $2::uuid)`,
			[]any{woIDP, woOrg}},
		{`INSERT INTO ziti_identities (id, name, org_id) VALUES ($1::uuid, 'alice-laptop', $2::uuid)`,
			[]any{woIdentity, woOrg}},
		{`INSERT INTO edr_posture_sources (id, org_id, name, provider) VALUES ($1::uuid, $2::uuid, 'CrowdStrike', 'crowdstrike')`,
			[]any{woSource, woOrg}},
	} {
		if _, err := db.Pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			cleanup()
			t.Fatalf("seed: %v", err)
		}
	}
	return &Service{db: db, logger: zap.NewNop()}, db, ctx, cleanup
}

func getJSON(t *testing.T, s *Service, ctx context.Context, params gin.Params,
	h func(*gin.Context)) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	c.Params = params
	h(c)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	return w, body
}

// The question: an identity provider is compromised — whose live sessions came
// through it?
func TestTheSessionListNamesTheProviderThatAuthenticatedEachSession(t *testing.T) {
	s, db, ctx, cleanup := writeOnlyFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO proxy_sessions (user_id, idp_id, org_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid)`,
			[]any{woIDP, woOrg}},
		{`INSERT INTO proxy_sessions (user_id, org_id) VALUES (gen_random_uuid(), $1::uuid)`, []any{woOrg}},
	} {
		if _, err := db.Pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}

	w, body := getJSON(t, s, ctx, nil, s.handleListSessions)
	if w.Code != http.StatusOK {
		t.Fatalf("listing sessions answered %d: %s", w.Code, w.Body.String())
	}
	sessions, _ := body["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("%d sessions listed, want 2: %s", len(sessions), w.Body.String())
	}

	var named, local int
	for _, raw := range sessions {
		sess, _ := raw.(map[string]any)
		switch sess["idp_name"] {
		case "Contoso Entra":
			named++
		case nil, "":
			local++
		default:
			t.Errorf("a session names provider %v", sess["idp_name"])
		}
	}
	if named != 1 {
		t.Errorf("%d of the listed sessions name the provider that authenticated them; the answer to "+
			"\"this IdP is compromised, whose sessions came through it?\" is this field: %s",
			named, w.Body.String())
	}
	if local != 1 {
		t.Errorf("%d sessions were reported as local; a session with no external provider must not "+
			"borrow one: %s", local, w.Body.String())
	}
}

// A session must not name another tenant's provider: that would leak the shape
// of their federation setup onto this tenant's page.
func TestASessionNeverNamesAnotherTenantsProvider(t *testing.T) {
	s, db, ctx, cleanup := writeOnlyFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	// The provider id is real, and belongs to somebody else.
	other := "00000000-0000-0000-0000-0000000000b9"
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO identity_providers (id, name, org_id) VALUES ($1::uuid, 'Other Tenant Okta', $2::uuid)`,
		other, woOtherOrg); err != nil {
		t.Fatalf("seed the other tenant's provider: %v", err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO proxy_sessions (user_id, idp_id, org_id) VALUES (gen_random_uuid(), $1::uuid, $2::uuid)`,
		other, woOrg); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	w, _ := getJSON(t, s, ctx, nil, s.handleListSessions)
	if strings.Contains(w.Body.String(), "Other Tenant Okta") {
		t.Errorf("the session list names another tenant's identity provider: %s", w.Body.String())
	}
}

// The question: this user's access was cut on a posture failure — which device
// caused it, and is it the right person's?
func TestAnEDRSourceListsTheDevicesItReported(t *testing.T) {
	s, db, ctx, cleanup := writeOnlyFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	if _, err := db.Pool.Exec(ctx, `
		INSERT INTO edr_device_mappings
			(org_id, source_id, external_device_id, match_value, identity_id, last_compliant, last_risk)
		VALUES ($1::uuid, $2::uuid, 'aid-1', 'alice@example.test', $3::uuid, false, 'high')`,
		woOrg, woSource, woIdentity); err != nil {
		t.Fatalf("seed the mapping: %v", err)
	}

	w, body := getJSON(t, s, ctx, gin.Params{{Key: "id", Value: woSource}}, s.handleListEDRDevices)
	if w.Code != http.StatusOK {
		t.Fatalf("listing EDR devices answered %d: %s", w.Code, w.Body.String())
	}
	devices, _ := body["devices"].([]any)
	if len(devices) != 1 {
		t.Fatalf("%d devices listed, want 1: %s", len(devices), w.Body.String())
	}
	d, _ := devices[0].(map[string]any)
	if d["external_device_id"] != "aid-1" {
		t.Errorf("the device is reported as %v", d["external_device_id"])
	}
	// The identity NAME is the point: an id answers nothing when the question
	// is whether the right person's laptop was matched.
	if d["identity_name"] != "alice-laptop" {
		t.Errorf("the device does not name the identity it matched (%v); matching is by email, hostname "+
			"or serial, so which identity was picked is the question: %s", d["identity_name"], w.Body.String())
	}
	if d["last_compliant"] != false {
		t.Errorf("the device's compliance verdict is %v; that verdict is what revoked the session",
			d["last_compliant"])
	}
}

func TestOneTenantsEDRSourceShowsNoOtherTenantsDevices(t *testing.T) {
	s, db, ctx, cleanup := writeOnlyFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	// Another tenant's source, with a device on it.
	otherSource := "00000000-0000-0000-0000-0000000000c9"
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO edr_posture_sources (id, org_id, name, provider) VALUES ($1::uuid, $2::uuid, 'Their Intune', 'intune')`,
			[]any{otherSource, woOtherOrg}},
		{`INSERT INTO edr_device_mappings (org_id, source_id, external_device_id, last_compliant)
		  VALUES ($1::uuid, $2::uuid, 'their-device', true)`, []any{woOtherOrg, otherSource}},
	} {
		if _, err := db.Pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Asking for their source by id, as this tenant.
	w, _ := getJSON(t, s, ctx, gin.Params{{Key: "id", Value: otherSource}}, s.handleListEDRDevices)
	if w.Code != http.StatusNotFound {
		t.Errorf("another tenant's EDR source answered %d, want 404: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "their-device") {
		t.Errorf("another tenant's devices were listed: %s", w.Body.String())
	}
}
