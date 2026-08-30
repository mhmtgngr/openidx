package access

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// ---------------------------------------------------------------------------
// Fake controller
// ---------------------------------------------------------------------------

// fakeController is a stand-in Ziti management API: it holds a policy/service
// set, answers the name-filter lookup EnsureServicePolicy uses, accepts
// create/update, and serves the list endpoints WITH meta.pagination.
type fakeController struct {
	mu sync.Mutex

	policies []ZitiServicePolicyInfo
	services []ZitiServiceInfo

	// pageSize, when > 0, is the number of rows served per page REGARDLESS of the
	// limit the client asked for — the controller is free to ignore `limit`, and
	// a pager that advances by the requested limit silently loses rows.
	pageSize int
	// omitPagination drops meta.pagination from list responses.
	omitPagination bool
	// listFails, when non-zero, is the status returned for every list call.
	listFails int

	nextID int
	calls  int
}

func (f *fakeController) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.Contains(r.URL.Path, "authenticate"):
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"token": "t"}})

		case strings.HasSuffix(r.URL.Path, "/service-policies") && r.Method == http.MethodGet:
			if name := filterName(r.URL.Query().Get("filter")); name != "" {
				var match []ZitiServicePolicyInfo
				for _, p := range f.policies {
					if p.Name == name {
						match = append(match, p)
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"data": match})
				return
			}
			f.writePage(w, r, policiesAsAny(f.policies))

		case strings.HasSuffix(r.URL.Path, "/services") && r.Method == http.MethodGet:
			f.writePage(w, r, servicesAsAny(f.services))

		case strings.HasSuffix(r.URL.Path, "/service-policies") && r.Method == http.MethodPost:
			var body ZitiServicePolicyInfo
			json.NewDecoder(r.Body).Decode(&body)
			f.nextID++
			body.ID = fmt.Sprintf("pol-%d", f.nextID)
			f.policies = append(f.policies, body)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"id": body.ID}})

		case strings.Contains(r.URL.Path, "/service-policies/") && r.Method == http.MethodPut:
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			var body ZitiServicePolicyInfo
			json.NewDecoder(r.Body).Decode(&body)
			for i := range f.policies {
				if f.policies[i].ID == id {
					body.ID = id
					f.policies[i] = body
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"id": id}})

		default:
			json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		}
	}
}

// writePage serves one page of rows, honoring the fake's own pageSize rather
// than the caller's limit.
func (f *fakeController) writePage(w http.ResponseWriter, r *http.Request, rows []any) {
	if f.listFails != 0 {
		w.WriteHeader(f.listFails)
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	size := len(rows)
	if f.pageSize > 0 {
		size = f.pageSize
	}
	end := offset + size
	if offset > len(rows) {
		offset = len(rows)
	}
	if end > len(rows) {
		end = len(rows)
	}
	out := map[string]any{"data": rows[offset:end]}
	if !f.omitPagination {
		out["meta"] = map[string]any{"pagination": map[string]any{
			"limit": size, "offset": offset, "totalCount": len(rows),
		}}
	}
	json.NewEncoder(w).Encode(out)
}

func policiesAsAny(in []ZitiServicePolicyInfo) []any {
	out := make([]any, 0, len(in))
	for _, p := range in {
		out = append(out, p)
	}
	return out
}

func servicesAsAny(in []ZitiServiceInfo) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// filterName extracts X from the `name="X"` filter EnsureServicePolicy sends.
func filterName(filter string) string {
	if !strings.HasPrefix(filter, `name="`) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(filter, `name="`), `"`)
}

func newFakeZiti(t *testing.T, f *fakeController, db *database.PostgresDB) (*ZitiManager, func()) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	cfg := MockConfig(t)
	cfg.ZitiCtrlURL = srv.URL
	zm := &ZitiManager{
		cfg:        cfg,
		logger:     zap.NewNop(),
		db:         db,
		mgmtToken:  "t",
		mgmtClient: srv.Client(),
	}
	return zm, srv.Close
}

// ---------------------------------------------------------------------------
// Paging (no DB)
// ---------------------------------------------------------------------------

// TestListAllEdgeEntitiesPaging proves the pager advances by what it RECEIVED.
// A controller that ignores the requested limit and serves 2 rows at a time
// still yields all 5.
func TestListAllEdgeEntitiesPaging(t *testing.T) {
	f := &fakeController{pageSize: 2}
	for i := 1; i <= 5; i++ {
		f.policies = append(f.policies, ZitiServicePolicyInfo{
			ID: fmt.Sprintf("p%d", i), Name: fmt.Sprintf("policy-%d", i), Type: "Dial",
		})
	}
	zm, closeFn := newFakeZiti(t, f, nil)
	defer closeFn()

	got, err := listAllEdgeEntities[ZitiServicePolicyInfo](zm, "service-policies")
	if err != nil {
		t.Fatalf("listAllEdgeEntities: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want all 5 policies across pages, got %d: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p.ID] = true
	}
	if len(seen) != 5 {
		t.Fatalf("want 5 distinct policies, got %d", len(seen))
	}
}

// TestListAllEdgeEntitiesRequiresPagination proves a response with no
// meta.pagination is an ERROR, not an empty success. Completeness is unknown
// there, and treating unknown as "the controller has nothing" is what would let
// a refresh delete every mirror row.
func TestListAllEdgeEntitiesRequiresPagination(t *testing.T) {
	f := &fakeController{omitPagination: true}
	f.policies = append(f.policies, ZitiServicePolicyInfo{ID: "p1", Name: "policy-1"})
	zm, closeFn := newFakeZiti(t, f, nil)
	defer closeFn()

	if _, err := listAllEdgeEntities[ZitiServicePolicyInfo](zm, "service-policies"); err == nil {
		t.Fatal("want an error when meta.pagination is absent, got nil")
	}
}

// ---------------------------------------------------------------------------
// DB-backed
// ---------------------------------------------------------------------------

const (
	mirrorOrgA = "00000000-0000-0000-0000-0000000000aa"
	mirrorOrgB = "00000000-0000-0000-0000-0000000000bb"
)

// mirrorSchema is the shape production has for the tables the mirror touches:
// both unique keys on ziti_services, the UNIQUE(ziti_id) the upsert keys on,
// and the route table attribution reads.
var mirrorSchema = []string{
	`CREATE TABLE ziti_service_policies (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		ziti_id VARCHAR(255) UNIQUE NOT NULL,
		name VARCHAR(255) NOT NULL,
		policy_type VARCHAR(10) NOT NULL,
		service_roles JSONB DEFAULT '[]',
		identity_roles JSONB DEFAULT '[]',
		is_system BOOLEAN DEFAULT false,
		org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010',
		created_at TIMESTAMPTZ DEFAULT NOW())`,
	`CREATE TABLE ziti_services (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		ziti_id VARCHAR(255) UNIQUE NOT NULL,
		name VARCHAR(255) UNIQUE NOT NULL,
		description TEXT, protocol VARCHAR(20) DEFAULT 'tcp',
		host VARCHAR(255) NOT NULL, port INTEGER NOT NULL,
		route_id UUID, enabled BOOLEAN DEFAULT true,
		org_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000010',
		updated_at TIMESTAMPTZ DEFAULT NOW())`,
	`CREATE TABLE proxy_routes (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		org_id UUID, to_url TEXT, enabled BOOLEAN DEFAULT true,
		ziti_enabled BOOLEAN DEFAULT false, ziti_service_name VARCHAR(255))`,
}

func newMirrorDB(t *testing.T) (*database.PostgresDB, func()) {
	t.Helper()
	db, cleanup := setupTestDB(t)
	if db == nil {
		return nil, func() {}
	}
	for _, q := range mirrorSchema {
		if _, err := db.Pool.Exec(context.Background(), q); err != nil {
			cleanup()
			t.Fatalf("schema: %v", err)
		}
	}
	return db, cleanup
}

func mustExec(t *testing.T, db *database.PostgresDB, q string, args ...any) {
	t.Helper()
	if _, err := db.Pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// mirrorRow reads one mirror row by policy id.
func mirrorRow(t *testing.T, db *database.PostgresDB, zitiID string) (name, ptype, org string, identityRoles []string, found bool) {
	t.Helper()
	var identJSON []byte
	err := db.Pool.QueryRow(context.Background(),
		`SELECT name, policy_type, org_id::text, identity_roles
		   FROM ziti_service_policies WHERE ziti_id = $1`, zitiID).
		Scan(&name, &ptype, &org, &identJSON)
	if err != nil {
		return "", "", "", nil, false
	}
	json.Unmarshal(identJSON, &identityRoles)
	return name, ptype, org, identityRoles, true
}

func countPolicies(t *testing.T, db *database.PostgresDB) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM ziti_service_policies`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// TestEnsureServicePolicyWritesMirror covers the write-through half: converging
// a policy on the controller also writes the mirror row, and a SECOND converge
// with different identity roles UPDATES it. The old writers used
// ON CONFLICT DO NOTHING, which is why the four stale rows on the box kept
// identity_roles no user identity carries and never self-corrected.
func TestEnsureServicePolicyWritesMirror(t *testing.T) {
	db, cleanup := newMirrorDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	f := &fakeController{}
	zm, closeFn := newFakeZiti(t, f, db)
	defer closeFn()
	ctx := context.Background()

	id, err := zm.EnsureServicePolicyForOrg(ctx, mirrorOrgA, "openidx-dial-web", "Dial",
		[]string{"#web"}, []string{"#access-proxy-clients"})
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	name, ptype, org, roles, found := mirrorRow(t, db, id)
	if !found {
		t.Fatal("want a mirror row after converging a policy, found none")
	}
	if name != "openidx-dial-web" || ptype != "Dial" || org != mirrorOrgA {
		t.Fatalf("mirror row mismatch: name=%q type=%q org=%q", name, ptype, org)
	}
	if len(roles) != 1 || roles[0] != "#access-proxy-clients" {
		t.Fatalf("want identity_roles [#access-proxy-clients], got %v", roles)
	}

	// Same policy, different identity roles — the mirror must follow.
	if _, err := zm.EnsureServicePolicyForOrg(ctx, mirrorOrgA, "openidx-dial-web", "Dial",
		[]string{"#web"}, []string{"#browzer-users"}); err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	_, _, _, roles, found = mirrorRow(t, db, id)
	if !found {
		t.Fatal("mirror row disappeared on re-converge")
	}
	if len(roles) != 1 || roles[0] != "#browzer-users" {
		t.Fatalf("DO NOTHING regression: want identity_roles [#browzer-users], got %v", roles)
	}
	if n := countPolicies(t, db); n != 1 {
		t.Fatalf("want the row updated in place, got %d rows", n)
	}
}

// TestEnsureServicePolicyWithoutOrgIsCountedNotStored covers R2: a platform-wide
// policy has no org, org_id is NOT NULL, so it is skipped and COUNTED — never
// attached to the default org.
func TestEnsureServicePolicyWithoutOrgIsCountedNotStored(t *testing.T) {
	db, cleanup := newMirrorDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	f := &fakeController{}
	zm, closeFn := newFakeZiti(t, f, db)
	defer closeFn()

	if _, err := zm.EnsureServicePolicy(context.Background(),
		"openidx-console-dial-enrolled-users", "Dial",
		[]string{"#openidx-console"}, []string{"#enrolled-users"}); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if n := countPolicies(t, db); n != 0 {
		t.Fatalf("want no mirror row for a policy with no org, got %d", n)
	}
	if got := zm.MirrorWritesSkippedNoOrg(); got != 1 {
		t.Fatalf("want the skip counted once, got %d", got)
	}
}

// TestRefreshZitiMirrorConverges covers the refresh half: insert missing, update
// drifted, delete only rows the COMPLETE listing positively proves absent.
func TestRefreshZitiMirrorConverges(t *testing.T) {
	db, cleanup := newMirrorDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	mustExec(t, db, `INSERT INTO proxy_routes (org_id, to_url, ziti_enabled, ziti_service_name)
	                 VALUES ($1,'http://web.internal:8080',true,'openidx-web')`, mirrorOrgA)
	// Drifted row: right policy, stale identity_roles (today's box state).
	mustExec(t, db, `INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, org_id)
	                 VALUES ('pol-drift','openidx-dial-openidx-web','Dial','["#openidx-web"]','["#access-proxy-clients"]',$1)`, mirrorOrgA)
	// Row whose policy no longer exists on the controller.
	mustExec(t, db, `INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, org_id)
	                 VALUES ('pol-gone','openidx-dial-deleted','Dial','["#openidx-web"]','["#access-proxy-clients"]',$1)`, mirrorOrgA)

	f := &fakeController{
		services: []ZitiServiceInfo{{ID: "svc-web", Name: "openidx-web"}},
		policies: []ZitiServicePolicyInfo{
			{ID: "pol-drift", Name: "openidx-dial-openidx-web", Type: "Dial",
				ServiceRoles: []string{"#openidx-web"}, IdentityRoles: []string{"#browzer-users"}},
			{ID: "pol-new", Name: "openidx-bind-openidx-web", Type: "Bind",
				ServiceRoles: []string{"#openidx-web"}, IdentityRoles: []string{"#ziti-routers"}},
		},
	}
	zm, closeFn := newFakeZiti(t, f, db)
	defer closeFn()

	stats, err := refreshZitiMirror(ctx, zm, db, zap.NewNop())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if stats.PoliciesInserted != 1 || stats.PoliciesUpdated != 1 || stats.PoliciesDeleted != 1 {
		t.Fatalf("want 1 inserted / 1 updated / 1 deleted, got %+v", stats)
	}
	if _, _, org, roles, found := mirrorRow(t, db, "pol-drift"); !found ||
		len(roles) != 1 || roles[0] != "#browzer-users" || org != mirrorOrgA {
		t.Fatalf("drifted row not converged: found=%v roles=%v org=%s", found, roles, org)
	}
	if _, _, org, _, found := mirrorRow(t, db, "pol-new"); !found || org != mirrorOrgA {
		t.Fatalf("missing row not inserted with the route's org: found=%v org=%s", found, org)
	}
	if _, _, _, _, found := mirrorRow(t, db, "pol-gone"); found {
		t.Fatal("row whose policy is absent from a complete listing should be deleted")
	}
	// The service mirror is filled in from the controller + the route's upstream.
	var host string
	var port int
	if err := db.Pool.QueryRow(ctx,
		`SELECT host, port FROM ziti_services WHERE name = 'openidx-web'`).Scan(&host, &port); err != nil {
		t.Fatalf("service mirror: %v", err)
	}
	if host != "web.internal" || port != 8080 {
		t.Fatalf("want the route's upstream mirrored, got %s:%d", host, port)
	}
}

// TestRefreshSkipsUnattributablePolicies covers R1/R2/R3 together: a policy whose
// serviceRoles match no route (platform-wide) and one whose roles span TWO orgs
// are both skipped and counted — and, critically, the rows they might have
// clobbered are neither written nor deleted.
func TestRefreshSkipsUnattributablePolicies(t *testing.T) {
	db, cleanup := newMirrorDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	mustExec(t, db, `INSERT INTO proxy_routes (org_id, to_url, ziti_enabled, ziti_service_name)
	                 VALUES ($1,'http://a.internal:80',true,'svc-a')`, mirrorOrgA)
	mustExec(t, db, `INSERT INTO proxy_routes (org_id, to_url, ziti_enabled, ziti_service_name)
	                 VALUES ($1,'http://b.internal:80',true,'svc-b')`, mirrorOrgB)

	f := &fakeController{
		services: []ZitiServiceInfo{{ID: "s-a", Name: "svc-a"}, {ID: "s-b", Name: "svc-b"}},
		policies: []ZitiServicePolicyInfo{
			// platform-wide: no route names openidx-console
			{ID: "pol-platform", Name: "openidx-console-dial-enrolled-users", Type: "Dial",
				ServiceRoles: []string{"#openidx-console"}, IdentityRoles: []string{"#enrolled-users"}},
			// spans two orgs
			{ID: "pol-cross", Name: "cross-org-dial", Type: "Dial",
				ServiceRoles: []string{"#svc-a", "#svc-b"}, IdentityRoles: []string{"#enrolled-users"}},
			// wildcard: names no particular service
			{ID: "pol-all", Name: "everything-dial", Type: "Dial",
				ServiceRoles: []string{"#all"}, IdentityRoles: []string{"#enrolled-users"}},
			// attributable
			{ID: "pol-a", Name: "openidx-dial-svc-a", Type: "Dial",
				ServiceRoles: []string{"#svc-a"}, IdentityRoles: []string{"#browzer-users"}},
		},
	}
	zm, closeFn := newFakeZiti(t, f, db)
	defer closeFn()

	stats, err := refreshZitiMirror(ctx, zm, db, zap.NewNop())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if stats.PoliciesSkipped != 3 {
		t.Fatalf("want 3 skipped (platform-wide, cross-org, wildcard), got %d (%v)",
			stats.PoliciesSkipped, stats.SkipReasons)
	}
	if len(stats.SkipReasons) != 3 {
		t.Fatalf("want the skips surfaced with reasons, got %v", stats.SkipReasons)
	}
	if stats.PoliciesInserted != 1 {
		t.Fatalf("want only the attributable policy stored, got %d", stats.PoliciesInserted)
	}
	for _, id := range []string{"pol-platform", "pol-cross", "pol-all"} {
		if _, _, _, _, found := mirrorRow(t, db, id); found {
			t.Fatalf("unattributable policy %s must NOT be stored", id)
		}
	}
	if n := countPolicies(t, db); n != 1 {
		t.Fatalf("want exactly the one attributable row, got %d", n)
	}
}

// TestRefreshDoesNotDeleteUnattributedRows covers R3 directly: an EXISTING mirror
// row for a policy the refresh could not attribute is still on the controller,
// so it must survive untouched rather than being pruned as "not mine".
func TestRefreshDoesNotDeleteUnattributedRows(t *testing.T) {
	db, cleanup := newMirrorDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	// The fixture needs BOTH shapes. An ATTRIBUTABLE policy is what makes the
	// prune path actually run: pruneMirrorPolicies refuses to act on an empty
	// `present` set, so a listing containing only the unattributable policy would
	// let the row survive for the wrong reason — the guard, not the rule — and a
	// build that stopped counting skipped policies as present would still pass.
	mustExec(t, db, `INSERT INTO proxy_routes (org_id, to_url, ziti_enabled, ziti_service_name)
	                 VALUES ($1,'http://a.internal:80',true,'svc-a')`, mirrorOrgA)

	// No route names openidx-console, so the policy is unattributable — but a row
	// for it already exists (written when a route did exist, say).
	mustExec(t, db, `INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, org_id)
	                 VALUES ('pol-platform','openidx-console-dial','Dial','["#openidx-console"]','["#enrolled-users"]',$1)`, mirrorOrgA)

	f := &fakeController{
		services: []ZitiServiceInfo{{ID: "s-a", Name: "svc-a"}},
		policies: []ZitiServicePolicyInfo{
			{ID: "pol-platform", Name: "openidx-console-dial", Type: "Dial",
				ServiceRoles: []string{"#openidx-console"}, IdentityRoles: []string{"#enrolled-users"}},
			// Attributable, so `present` is non-empty and the prune really runs.
			{ID: "pol-a", Name: "openidx-dial-svc-a", Type: "Dial",
				ServiceRoles: []string{"#svc-a"}, IdentityRoles: []string{"#browzer-users"}},
		},
	}
	zm, closeFn := newFakeZiti(t, f, db)
	defer closeFn()

	stats, err := refreshZitiMirror(ctx, zm, db, zap.NewNop())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if stats.PoliciesSkipped != 1 {
		t.Fatalf("want the policy skipped, got %+v", stats)
	}
	// Precondition for this test to mean anything: the prune had something to
	// compare against. Without the attributable policy, `present` is empty and
	// pruneMirrorPolicies short-circuits before it can delete anything.
	if _, _, _, _, found := mirrorRow(t, db, "pol-a"); !found {
		t.Fatal("fixture precondition: the attributable policy must be mirrored so the prune path runs")
	}
	if stats.PoliciesDeleted != 0 {
		t.Fatalf("want no deletions, got %d", stats.PoliciesDeleted)
	}
	if _, _, _, _, found := mirrorRow(t, db, "pol-platform"); !found {
		t.Fatal("an unattributable row that still exists on the controller must not be deleted")
	}
}

// TestRefreshFailureLeavesMirrorUnchanged covers R4: a controller failure mid-pass
// must change nothing at all — in particular it must not prune the mirror down to
// what a partial listing happened to show.
func TestRefreshFailureLeavesMirrorUnchanged(t *testing.T) {
	db, cleanup := newMirrorDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	mustExec(t, db, `INSERT INTO proxy_routes (org_id, to_url, ziti_enabled, ziti_service_name)
	                 VALUES ($1,'http://web.internal:8080',true,'openidx-web')`, mirrorOrgA)
	mustExec(t, db, `INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, org_id)
	                 VALUES ('pol-1','openidx-dial-openidx-web','Dial','["#openidx-web"]','["#browzer-users"]',$1)`, mirrorOrgA)

	t.Run("controller unreachable", func(t *testing.T) {
		f := &fakeController{listFails: http.StatusInternalServerError}
		zm, closeFn := newFakeZiti(t, f, db)
		defer closeFn()
		if _, err := refreshZitiMirror(ctx, zm, db, zap.NewNop()); err == nil {
			t.Fatal("want an error when the controller listing fails")
		}
		if n := countPolicies(t, db); n != 1 {
			t.Fatalf("mirror must be untouched on failure, got %d rows", n)
		}
	})

	t.Run("listing without pagination is not an empty controller", func(t *testing.T) {
		f := &fakeController{omitPagination: true}
		zm, closeFn := newFakeZiti(t, f, db)
		defer closeFn()
		if _, err := refreshZitiMirror(ctx, zm, db, zap.NewNop()); err == nil {
			t.Fatal("want an error when meta.pagination is absent")
		}
		if n := countPolicies(t, db); n != 1 {
			t.Fatalf("mirror must be untouched, got %d rows", n)
		}
		if _, _, _, roles, found := mirrorRow(t, db, "pol-1"); !found || len(roles) != 1 {
			t.Fatalf("row altered by a failed refresh: found=%v roles=%v", found, roles)
		}
	})

	t.Run("services listing failure aborts before any write", func(t *testing.T) {
		// Policies list fine, services do not: nothing may be written, because a
		// half-read controller is not evidence of anything.
		f := &fakeController{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/services") {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			f.handler()(w, r)
		}))
		defer srv.Close()
		cfg := MockConfig(t)
		cfg.ZitiCtrlURL = srv.URL
		zm := &ZitiManager{cfg: cfg, logger: zap.NewNop(), db: db, mgmtToken: "t", mgmtClient: srv.Client()}
		f.policies = []ZitiServicePolicyInfo{{ID: "pol-x", Name: "new-policy", Type: "Dial",
			ServiceRoles: []string{"#openidx-web"}, IdentityRoles: []string{"#browzer-users"}}}
		if _, err := refreshZitiMirror(ctx, zm, db, zap.NewNop()); err == nil {
			t.Fatal("want an error when the services listing fails")
		}
		if n := countPolicies(t, db); n != 1 {
			t.Fatalf("no write may happen before both listings succeed, got %d rows", n)
		}
	})
}

// TestRefreshThenCollectZitiPillar is the end-to-end case that is broken on the
// live box: an identity carrying `browzer-users` against a `#browzer-users` Dial
// policy resolves to a real, named, reachable service — and the self endpoint
// enriches it with the upstream's host/port.
func TestRefreshThenCollectZitiPillar(t *testing.T) {
	db, cleanup := newMirrorDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	ctx := context.Background()

	// The pillar reads three more tables.
	for _, q := range []string{
		`CREATE TABLE ziti_identities (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			ziti_id VARCHAR(255) NOT NULL, name VARCHAR(255) NOT NULL,
			user_id UUID, org_id UUID, enrolled BOOLEAN DEFAULT false,
			attributes JSONB DEFAULT '[]')`,
		`CREATE TABLE enrolled_agents (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			agent_id VARCHAR(255), platform VARCHAR(64), status VARCHAR(64),
			compliance_status VARCHAR(64), ziti_identity_id VARCHAR(255),
			enrolled_by_user_id UUID, enrolled_at TIMESTAMPTZ DEFAULT NOW(),
			last_seen_at TIMESTAMPTZ)`,
		`CREATE TABLE known_devices (user_id UUID, org_id UUID, trusted BOOLEAN DEFAULT false)`,
	} {
		mustExec(t, db, q)
	}

	const user = "11111111-1111-1111-1111-111111111111"
	mustExec(t, db, `INSERT INTO proxy_routes (org_id, to_url, ziti_enabled, ziti_service_name)
	                 VALUES ($1,'http://netgraph.internal:8080',true,'openidx-Netgraph')`, mirrorOrgA)
	// A user identity as ziti_user_sync writes it: role attributes, no
	// #access-proxy-clients anywhere.
	mustExec(t, db, `INSERT INTO ziti_identities (ziti_id, name, user_id, org_id, enrolled, attributes)
	                 VALUES ('zid-1','alice',$1,$2,true,'["browzer-users","enrolled-users"]')`, user, mirrorOrgA)
	// The stale state the box is in: a Dial row keyed to an identity role that no
	// user carries, so the pillar matches nothing.
	mustExec(t, db, `INSERT INTO ziti_service_policies (ziti_id, name, policy_type, service_roles, identity_roles, org_id)
	                 VALUES ('pol-dial','openidx-dial-openidx-Netgraph','Dial','["#openidx-Netgraph"]','["#access-proxy-clients"]',$1)`, mirrorOrgA)

	s := &Service{db: db, logger: zap.NewNop()}
	var before AccessMapZiti
	if err := s.collectZitiPillar(ctx, mirrorOrgA, user, &before); err != nil {
		t.Fatalf("pillar (before): %v", err)
	}
	if len(before.ReachableServices) != 0 {
		t.Fatalf("precondition: the stale mirror should resolve nothing, got %v", before.ReachableServices)
	}

	// What the controller actually says.
	f := &fakeController{
		services: []ZitiServiceInfo{{ID: "svc-ng", Name: "openidx-Netgraph"}},
		policies: []ZitiServicePolicyInfo{
			{ID: "pol-dial", Name: "openidx-dial-openidx-Netgraph", Type: "Dial",
				ServiceRoles: []string{"#openidx-Netgraph"}, IdentityRoles: []string{"#browzer-users"}},
		},
	}
	zm, closeFn := newFakeZiti(t, f, db)
	defer closeFn()
	if _, err := refreshZitiMirror(ctx, zm, db, zap.NewNop()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	var after AccessMapZiti
	if err := s.collectZitiPillar(ctx, mirrorOrgA, user, &after); err != nil {
		t.Fatalf("pillar (after): %v", err)
	}
	if len(after.ReachableServices) != 1 || after.ReachableServices[0] != "openidx-Netgraph" {
		t.Fatalf("want [openidx-Netgraph] reachable, got %v", after.ReachableServices)
	}

	resp, err := s.myZitiServices(ctx, mirrorOrgA, user)
	if err != nil {
		t.Fatalf("myZitiServices: %v", err)
	}
	if len(resp.Services) != 1 || resp.Services[0].Name != "openidx-Netgraph" {
		t.Fatalf("want one named app, got %+v", resp.Services)
	}
	if resp.Services[0].Host != "netgraph.internal" || resp.Services[0].Port != 8080 {
		t.Fatalf("want the app enriched with its upstream, got %+v", resp.Services[0])
	}
}
