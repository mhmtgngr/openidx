package access

import (
	"bytes"
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

// Three more of the "network changed, record did not" handlers from 2dc69b3d.
//
// The delete is the same shape as the service delete. The two updates are the
// worse half of the class, and worth separating: an operator changes a policy's
// service and identity roles, the controller takes them, the mirror write
// fails, and the console goes on showing the OLD roles for a policy the overlay
// is enforcing differently. Role attributes are what the overlay's policies
// match on, so the console is not merely stale -- it is wrong about who can
// reach what.

const zitiIdentitySchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS ziti_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255), name VARCHAR(255), user_id UUID,
    attributes JSONB DEFAULT '[]', enrollment_jwt TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW(), org_id UUID);
CREATE TABLE IF NOT EXISTS ziti_service_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ziti_id VARCHAR(255), name VARCHAR(255), policy_type VARCHAR(16),
    service_roles JSONB DEFAULT '[]', identity_roles JSONB DEFAULT '[]',
    is_system BOOLEAN DEFAULT false, org_id UUID);`

const (
	identOrg    = "00000000-0000-0000-0000-000000000101"
	identRow    = "00000000-0000-0000-0000-000000000102"
	policyRow   = "00000000-0000-0000-0000-000000000103"
	identZitiID = "ident-1"
)

func identityFixture(t *testing.T) (*Service, *zitiStub, *database.PostgresDB, context.Context, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, nil, nil, nil, func() {}
	}
	gin.SetMode(gin.TestMode)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: identOrg})

	if _, err := db.Pool.Exec(ctx, zitiIdentitySchema); err != nil {
		cleanup()
		t.Fatalf("schema: %v", err)
	}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO ziti_identities (id, ziti_id, name, attributes, org_id)
		  VALUES ($1::uuid, $2, 'a-device', '["old-attr"]'::jsonb, $3::uuid)`,
			[]any{identRow, identZitiID, identOrg}},
		{`INSERT INTO ziti_service_policies (id, ziti_id, name, policy_type, service_roles, identity_roles, org_id)
		  VALUES ($1::uuid, 'pol-1', 'a-policy', 'Dial', '["#old-svc"]'::jsonb, '["#old-id"]'::jsonb, $2::uuid)`,
			[]any{policyRow, identOrg}},
	} {
		if _, err := db.Pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			cleanup()
			t.Fatalf("seed: %v", err)
		}
	}

	stub := newZitiStub(t)
	stub.on("DELETE /edge/management/v1/identities", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	stub.on("PATCH /edge/management/v1/identities", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	stub.on("PUT /edge/management/v1/service-policies", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	svc := &Service{
		db:           db,
		logger:       zap.NewNop(),
		zitiProvider: newZitiProviderWith(zitiManagerAgainst(t, stub, db)),
	}
	return svc, stub, db, ctx, cleanup
}

// call drives one handler with a JSON body and an :id parameter.
func call(t *testing.T, s *Service, ctx context.Context, method, id string, body any,
	h func(*gin.Context)) *httptest.ResponseRecorder {
	t.Helper()
	var buf []byte
	if body != nil {
		var err error
		if buf, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, "/x/"+id, bytes.NewReader(buf)).WithContext(ctx)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Set("roles", []string{"admin"})
	h(c)
	return w
}

// refuseWrites installs a trigger refusing the named operation on a table.
func refuseWrites(t *testing.T, db *database.PostgresDB, ctx context.Context, table, event string) {
	t.Helper()
	fn := "refuse_" + table + "_" + strings.ToLower(event)
	if _, err := db.Pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'refused by test'; END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER `+fn+`_trg BEFORE `+event+` ON `+table+`
		FOR EACH ROW EXECUTE FUNCTION `+fn+`();`); err != nil {
		t.Fatalf("install refusal trigger on %s %s: %v", table, event, err)
	}
}

func TestDeletingAZitiIdentityRemovesItFromBothSides(t *testing.T) {
	s, stub, db, ctx, cleanup := identityFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	w := call(t, s, ctx, http.MethodDelete, identRow, nil, s.handleDeleteZitiIdentity)
	if w.Code != http.StatusOK {
		t.Fatalf("deleting an identity answered %d: %s (controller saw %v)", w.Code, w.Body.String(), stub.received())
	}
	if !stub.saw("DELETE /edge/management/v1/identities/" + identZitiID) {
		t.Errorf("the identity was not deleted on the controller; calls: %v", stub.received())
	}
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM ziti_identities`).Scan(&n); err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if n != 0 {
		t.Errorf("the identity row survives a successful delete")
	}
}

func TestAZitiIdentityDeleteThatKeepsItsRecordDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, cleanup := identityFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "ziti_identities", "DELETE")

	w := call(t, s, ctx, http.MethodDelete, identRow, nil, s.handleDeleteZitiIdentity)
	if w.Code == http.StatusOK {
		t.Fatalf("the identity is gone from the overlay, its record is not, and the handler answered "+
			"200: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "removed from the network") {
		t.Errorf("the response does not say the identity WAS removed from the network: %s", w.Body.String())
	}
	if !stub.saw("DELETE /edge/management/v1/identities/" + identZitiID) {
		t.Errorf("the controller delete never happened; calls: %v", stub.received())
	}
}

// The updates. Losing the mirror here is not a stale list -- the console shows
// roles the overlay is no longer enforcing, and role attributes are exactly
// what policies match on.
func TestAServicePolicyUpdateThatKeepsTheOldRolesDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, cleanup := identityFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "ziti_service_policies", "UPDATE")

	body := map[string]any{
		"name": "a-policy", "type": "Dial",
		"service_roles": []string{"#new-svc"}, "identity_roles": []string{"#new-id"},
	}
	w := call(t, s, ctx, http.MethodPut, policyRow, body, s.handleUpdateServicePolicy)
	if w.Code == http.StatusOK {
		t.Fatalf("the policy was changed on the network, the record was not, and the handler answered "+
			"200. The console shows roles the overlay is not enforcing: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "previous roles") {
		t.Errorf("the response does not warn that the console still shows the old roles: %s", w.Body.String())
	}
	if !stub.saw("PUT /edge/management/v1/service-policies/pol-1") {
		t.Errorf("the controller update never happened, so this proves nothing about the split; "+
			"calls: %v", stub.received())
	}

	// And the stored roles really are the old ones — which is what makes the
	// warning true rather than decorative.
	var svcRoles string
	if err := db.Pool.QueryRow(ctx,
		`SELECT service_roles::text FROM ziti_service_policies WHERE id = $1::uuid`, policyRow).Scan(&svcRoles); err != nil {
		t.Fatalf("read the policy back: %v", err)
	}
	if !strings.Contains(svcRoles, "old-svc") {
		t.Errorf("service_roles = %s; the test's premise (the mirror write was refused) did not hold", svcRoles)
	}
}

func TestAnIdentityAttributePatchThatKeepsTheOldAttributesDoesNotReportSuccess(t *testing.T) {
	s, stub, db, ctx, cleanup := identityFixture(t)
	if s == nil {
		return
	}
	defer cleanup()
	refuseWrites(t, db, ctx, "ziti_identities", "UPDATE")

	w := call(t, s, ctx, http.MethodPatch, identRow,
		map[string]any{"attributes": []string{"new-attr"}}, s.handlePatchIdentityAttributes)
	if w.Code == http.StatusOK {
		t.Fatalf("the attributes were changed on the overlay, the record was not, and the handler "+
			"answered 200. Policies match on those attributes: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "previous attributes") {
		t.Errorf("the response does not warn that the console still shows the old attributes: %s", w.Body.String())
	}
	if !stub.saw("PATCH /edge/management/v1/identities/" + identZitiID) {
		t.Errorf("the controller patch never happened; calls: %v", stub.received())
	}
}

// The positive controls: both updates land on both sides when nothing refuses.
func TestTheUpdatesReachBothSidesWhenNothingRefuses(t *testing.T) {
	s, stub, db, ctx, cleanup := identityFixture(t)
	if s == nil {
		return
	}
	defer cleanup()

	w := call(t, s, ctx, http.MethodPut, policyRow, map[string]any{
		"name": "a-policy", "type": "Dial",
		"service_roles": []string{"#new-svc"}, "identity_roles": []string{"#new-id"},
	}, s.handleUpdateServicePolicy)
	if w.Code != http.StatusOK {
		t.Fatalf("updating a policy answered %d: %s (controller saw %v)", w.Code, w.Body.String(), stub.received())
	}

	w = call(t, s, ctx, http.MethodPatch, identRow,
		map[string]any{"attributes": []string{"new-attr"}}, s.handlePatchIdentityAttributes)
	if w.Code != http.StatusOK {
		t.Fatalf("patching attributes answered %d: %s", w.Code, w.Body.String())
	}

	var svcRoles, attrs string
	if err := db.Pool.QueryRow(ctx,
		`SELECT service_roles::text FROM ziti_service_policies WHERE id = $1::uuid`, policyRow).Scan(&svcRoles); err != nil {
		t.Fatalf("read the policy back: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT attributes::text FROM ziti_identities WHERE id = $1::uuid`, identRow).Scan(&attrs); err != nil {
		t.Fatalf("read the identity back: %v", err)
	}
	if !strings.Contains(svcRoles, "new-svc") {
		t.Errorf("the policy's stored service_roles are %s after a successful update", svcRoles)
	}
	if !strings.Contains(attrs, "new-attr") {
		t.Errorf("the identity's stored attributes are %s after a successful patch", attrs)
	}
}
