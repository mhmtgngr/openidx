package access

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// ---------------------------------------------------------------------------
// The extraction is behaviour-preserving
// ---------------------------------------------------------------------------

// TestReachabilityForIdentityMatchesMirrorPath proves the helper extracted out
// of collectZitiPillar computes exactly what the old inline loop computed for
// the same input. The report and the access map now share that helper, so this
// is what says the sharing changed nothing on the mirror side.
//
// legacyReachability below is a verbatim copy of the pre-extraction loop
// (policyAppliesToIdentity + resolveServiceRoles + a sorted union). If someone
// changes the matching rules in a way that alters mirror-path answers, these
// two diverge and this test fails.
func TestReachabilityForIdentityMatchesMirrorPath(t *testing.T) {
	byID := map[string]string{"s1": "prod-db", "s2": "jumphost"}
	all := []string{"prod-db", "jumphost"}

	cases := []struct {
		name     string
		policies []zitiDialPolicy
		zitiID   string
		attrs    []string
	}{
		{"blanket policy", []zitiDialPolicy{{Name: "p", IdentityRoles: []string{"#all"}, ServiceRoles: []string{"#all"}}}, "z1", nil},
		{"pinned identity, id service role", []zitiDialPolicy{{Name: "p", IdentityRoles: []string{"@z1"}, ServiceRoles: []string{"@s1"}}}, "z1", nil},
		{"attribute match", []zitiDialPolicy{{Name: "p", IdentityRoles: []string{"#browzer-users"}, ServiceRoles: []string{"@s2"}}}, "z1", []string{"browzer-users"}},
		{"no match", []zitiDialPolicy{{Name: "p", IdentityRoles: []string{"#sre"}, ServiceRoles: []string{"#all"}}}, "z1", []string{"browzer-users"}},
		{"unresolvable tag kept as intent", []zitiDialPolicy{{Name: "p", IdentityRoles: []string{"#all"}, ServiceRoles: []string{"#web-apps"}}}, "z1", nil},
		{"several policies, overlapping services", []zitiDialPolicy{
			{Name: "a", IdentityRoles: []string{"#all"}, ServiceRoles: []string{"@s1"}},
			{Name: "b", IdentityRoles: []string{"@z1"}, ServiceRoles: []string{"#all"}},
			{Name: "c", IdentityRoles: []string{"#nobody"}, ServiceRoles: []string{"@s2"}},
		}, "z1", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantPolicies, wantServices := legacyReachability(tc.policies, tc.zitiID, tc.attrs, byID, all)
			gotPolicies, gotServices := reachabilityForIdentity(tc.policies, tc.zitiID, tc.attrs,
				zitiServiceIndex{byZitiID: byID, all: all})

			if len(gotServices) != len(wantServices) {
				t.Fatalf("reachable services = %v, want %v", gotServices, wantServices)
			}
			for i := range wantServices {
				if gotServices[i] != wantServices[i] {
					t.Fatalf("reachable services = %v, want %v", gotServices, wantServices)
				}
			}
			if len(gotPolicies) != len(wantPolicies) {
				t.Fatalf("applied policies = %+v, want %+v", gotPolicies, wantPolicies)
			}
			for i := range wantPolicies {
				if gotPolicies[i].Name != wantPolicies[i].Name {
					t.Fatalf("applied policy %d = %q, want %q", i, gotPolicies[i].Name, wantPolicies[i].Name)
				}
				if len(gotPolicies[i].Services) != len(wantPolicies[i].Services) {
					t.Fatalf("policy %q services = %v, want %v",
						gotPolicies[i].Name, gotPolicies[i].Services, wantPolicies[i].Services)
				}
			}
		})
	}
}

// legacyReachability is the pre-extraction inline loop from collectZitiPillar,
// kept here as the reference the extraction is compared against.
func legacyReachability(policies []zitiDialPolicy, zitiID string, attrs []string,
	svcByZitiID map[string]string, allServices []string) ([]AccessMapDialPolicy, []string) {
	var applied []AccessMapDialPolicy
	reachable := map[string]bool{}
	for _, p := range policies {
		if !policyAppliesToIdentity(p.IdentityRoles, zitiID, attrs) {
			continue
		}
		resolved := resolveServiceRoles(p.ServiceRoles, svcByZitiID, allServices)
		applied = append(applied, AccessMapDialPolicy{Name: p.Name, Services: resolved})
		for _, svc := range resolved {
			reachable[svc] = true
		}
	}
	var out []string
	for svc := range reachable {
		out = append(out, svc)
	}
	// sorted the same way collectZitiPillar sorted it
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return applied, out
}

// TestReachabilityResolvesServiceTagsFromController: on the real box a Dial
// policy's service role is `#<serviceName>` and the service carries its own
// name as a role attribute (ziti_reconciler.ensureServiceAttr). Resolving that
// tag is therefore not a nicety — without it every real policy resolves to a
// literal "#name" string that matches no application, i.e. back to "nobody
// reaches anything, safe to enforce".
func TestReachabilityResolvesServiceTagsFromController(t *testing.T) {
	idx := zitiServiceIndex{
		byZitiID: map[string]string{"s1": "openidx-es-dev"},
		all:      []string{"openidx-es-dev"},
		byAttr:   map[string][]string{"openidx-es-dev": {"openidx-es-dev"}},
	}
	_, got := reachabilityForIdentity(
		[]zitiDialPolicy{{Name: "openidx-dial-openidx-es-dev",
			IdentityRoles: []string{"#browzer-users"}, ServiceRoles: []string{"#openidx-es-dev"}}},
		"z1", []string{"browzer-users"}, idx)
	if len(got) != 1 || got[0] != "openidx-es-dev" {
		t.Fatalf("tag service role should resolve to the service name, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// The report reads the controller, and says so when it cannot
// ---------------------------------------------------------------------------

const (
	reportOrg   = "00000000-0000-0000-0000-0000000000ab"
	reportAlice = "11111111-0000-0000-0000-0000000000a1"
	reportBob   = "11111111-0000-0000-0000-0000000000b1"
	reportApp   = "22222222-0000-0000-0000-0000000000a1"
	reportRoute = "33333333-0000-0000-0000-0000000000a1"
	reportSvc   = "openidx-es-dev"
)

// reportSchema adds the assignment-side tables crossPillarSchema does not
// carry, plus the proxy_routes column the report joins on.
var reportSchema = []string{
	`CREATE TABLE IF NOT EXISTS applications (
		id UUID PRIMARY KEY, org_id UUID NOT NULL, name VARCHAR(255) NOT NULL,
		route_id UUID, enabled BOOLEAN NOT NULL DEFAULT true)`,
	`CREATE TABLE IF NOT EXISTS user_application_assignments (
		user_id UUID NOT NULL, application_id UUID NOT NULL, org_id UUID NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS group_application_assignments (
		group_id UUID NOT NULL, application_id UUID NOT NULL, org_id UUID NOT NULL)`,
	`ALTER TABLE proxy_routes ADD COLUMN IF NOT EXISTS ziti_service_name VARCHAR(255)`,
}

// reportResponse is the shape the console consumes.
type reportResponse struct {
	Entries []ReportEntry `json:"entries"`
	Summary struct {
		Users           int `json:"users"`
		Applications    int `json:"applications"`
		WouldDeny       int `json:"would_deny"`
		IncompleteUsers int `json:"incomplete_users"`
	} `json:"summary"`
	Assignments        []AssignmentEntry `json:"assignments"`
	ReachabilitySource string            `json:"reachability_source"`
	ReachabilityError  string            `json:"reachability_error"`
}

// TestAssignmentReportReadsController is the regression test for the defect
// this endpoint shipped with: it answered "who can reach what today" out of the
// local ziti_service_policies / ziti_services mirror, which the reconciler
// never writes. The mirror here is seeded so that a mirror-backed report gives
// the exact INVERSE of the truth (it says bob reaches the app and alice does
// not; the controller says the opposite). If anyone reinstates the mirror path,
// this test reports the wrong user and fails.
func TestAssignmentReportReadsController(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	ctx := orgctx.With(context.Background(), orgctx.Org{ID: reportOrg})
	for _, stmt := range append(append([]string{}, crossPillarSchema...), reportSchema...) {
		if _, err := db.Pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	seed := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'alice','alice@x.io')`,
			[]any{reportAlice, reportOrg}},
		{`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'bob','bob@x.io')`,
			[]any{reportBob, reportOrg}},
		// alice carries #browzer-users, bob carries #enrolled-users. The
		// controller policy below grants browzer-users; the mirror policy
		// grants enrolled-users. The two disagree on purpose.
		{`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled, attributes)
		  VALUES (gen_random_uuid(),$1,'z-alice','alice',$2,true,'["browzer-users"]'::jsonb)`,
			[]any{reportOrg, reportAlice}},
		{`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled, attributes)
		  VALUES (gen_random_uuid(),$1,'z-bob','bob',$2,true,'["enrolled-users"]'::jsonb)`,
			[]any{reportOrg, reportBob}},
		{`INSERT INTO proxy_routes (id, name, ziti_enabled, ziti_service_name) VALUES ($1,'es-dev',true,$2)`,
			[]any{reportRoute, reportSvc}},
		{`INSERT INTO applications (id, org_id, name, route_id, enabled) VALUES ($1,$2,'Es-Dev',$3,true)`,
			[]any{reportApp, reportOrg, reportRoute}},
		// The stale mirror: says the app is dialable by #enrolled-users (bob),
		// which is what App Publish/manual creates leave behind.
		{`INSERT INTO ziti_services (id, org_id, ziti_id, name, enabled) VALUES (gen_random_uuid(),$1,'s1',$2,true)`,
			[]any{reportOrg, reportSvc}},
		{`INSERT INTO ziti_service_policies (id, org_id, name, policy_type, service_roles, identity_roles)
		  VALUES (gen_random_uuid(),$1,'mirror-dial','Dial','["@s1"]'::jsonb,'["#enrolled-users"]'::jsonb)`,
			[]any{reportOrg}},
	}
	for _, st := range seed {
		if _, err := db.Pool.Exec(ctx, st.sql, st.args...); err != nil {
			t.Fatalf("seed %q: %v", st.sql, err)
		}
	}

	newCtx := func() (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/assignment-report", nil)
		c.Request = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: reportOrg}))
		return c, w
	}
	decode := func(t *testing.T, w *httptest.ResponseRecorder) reportResponse {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", w.Code, w.Body.String())
		}
		var got reportResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		return got
	}

	t.Run("reach comes from the controller, not the mirror", func(t *testing.T) {
		// The live controller: only #browzer-users (alice) may dial, and the
		// service role is the `#<name>` tag the reconciler actually emits.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case containsPath(r, "service-policies"):
				_, _ = w.Write([]byte(`{"data":[
					{"id":"p1","name":"openidx-dial-openidx-es-dev","type":"Dial",
					 "serviceRoles":["#openidx-es-dev"],"identityRoles":["#browzer-users"]},
					{"id":"p2","name":"openidx-bind-openidx-es-dev","type":"Bind",
					 "serviceRoles":["#openidx-es-dev"],"identityRoles":["#all"]}]}`))
			case containsPath(r, "services"):
				_, _ = w.Write([]byte(`{"data":[
					{"id":"s-live","name":"openidx-es-dev","roleAttributes":["openidx-es-dev"]}]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		s := reportService(t, db, srv.URL)

		// First prove the mirror really does disagree, so the assertions below
		// are a genuine controller-vs-mirror discrimination and not a test that
		// would pass either way.
		var bobPillar, alicePillar AccessMapZiti
		if err := s.collectZitiPillar(ctx, reportOrg, reportBob, &bobPillar); err != nil {
			t.Fatalf("mirror pillar (bob): %v", err)
		}
		if err := s.collectZitiPillar(ctx, reportOrg, reportAlice, &alicePillar); err != nil {
			t.Fatalf("mirror pillar (alice): %v", err)
		}
		if len(bobPillar.ReachableServices) != 1 || bobPillar.ReachableServices[0] != reportSvc {
			t.Fatalf("fixture is not discriminating: the mirror should say bob reaches %s, got %v",
				reportSvc, bobPillar.ReachableServices)
		}
		if len(alicePillar.ReachableServices) != 0 {
			t.Fatalf("fixture is not discriminating: the mirror should say alice reaches nothing, got %v",
				alicePillar.ReachableServices)
		}

		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.ReachabilitySource != ReachabilityFromController {
			t.Fatalf("reachability_source = %q, want %q", got.ReachabilitySource, ReachabilityFromController)
		}
		if got.Summary.IncompleteUsers != 0 {
			t.Fatalf("incomplete_users = %d, want 0", got.Summary.IncompleteUsers)
		}
		if len(got.Entries) != 1 {
			t.Fatalf("want exactly one would-deny entry (alice reaches Es-Dev unassigned), got %+v", got.Entries)
		}
		if got.Entries[0].UserID != reportAlice {
			t.Fatalf("would-deny entry is for %q (%s); the mirror says bob, the controller says alice — "+
				"a bob entry means the report read the mirror",
				got.Entries[0].Username, got.Entries[0].UserID)
		}
		if got.Entries[0].ApplicationName != "Es-Dev" {
			t.Errorf("application name = %q, want Es-Dev", got.Entries[0].ApplicationName)
		}
	})

	t.Run("no ziti manager reports unavailable, never a clean report", func(t *testing.T) {
		s := &Service{db: db, logger: zap.NewNop()} // zitiProvider nil => s.ziti() nil
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.ReachabilitySource != ReachabilityUnavailable {
			t.Fatalf("reachability_source = %q, want %q", got.ReachabilitySource, ReachabilityUnavailable)
		}
		if got.Summary.IncompleteUsers != 2 {
			t.Fatalf("incomplete_users = %d, want 2 (every user's reach is unknown)", got.Summary.IncompleteUsers)
		}
		if len(got.Entries) != 0 || got.Summary.WouldDeny != 0 {
			t.Fatalf("reach is unknown, so the diff must be empty rather than mirror-derived: %+v", got.Entries)
		}
		if got.ReachabilityError == "" {
			t.Error("reachability_error must say why reach is unknown")
		}
	})

	t.Run("controller failure reports unavailable with the reason", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		s := reportService(t, db, srv.URL)
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.ReachabilitySource != ReachabilityUnavailable {
			t.Fatalf("reachability_source = %q, want %q", got.ReachabilitySource, ReachabilityUnavailable)
		}
		if got.Summary.IncompleteUsers != 2 {
			t.Fatalf("incomplete_users = %d, want 2", got.Summary.IncompleteUsers)
		}
		if len(got.Entries) != 0 {
			t.Fatalf("a failed controller read must not fall back to the mirror: %+v", got.Entries)
		}
		if got.ReachabilityError == "" {
			t.Error("reachability_error must carry the controller failure")
		}
	})

	t.Run("assignment half survives an unavailable controller", func(t *testing.T) {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO user_application_assignments (user_id, application_id, org_id) VALUES ($1,$2,$3)`,
			reportBob, reportApp, reportOrg); err != nil {
			t.Fatalf("seed assignment: %v", err)
		}
		defer func() {
			_, _ = db.Pool.Exec(ctx, `DELETE FROM user_application_assignments WHERE user_id = $1`, reportBob)
		}()

		s := &Service{db: db, logger: zap.NewNop()}
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if len(got.Assignments) != 1 || got.Assignments[0].UserID != reportBob {
			t.Fatalf("the DB-only assignment half must still be reported, got %+v", got.Assignments)
		}
		if got.ReachabilitySource != ReachabilityUnavailable {
			t.Fatalf("reachability_source = %q, want %q", got.ReachabilitySource, ReachabilityUnavailable)
		}
	})
}

// containsPath reports whether the request path ends in the given management
// API collection (…/service-policies vs …/services).
func containsPath(r *http.Request, collection string) bool {
	return r.URL.Path == "/edge/management/v1/"+collection
}

// reportService builds a Service whose ziti() points at a fake controller.
func reportService(t *testing.T, db *database.PostgresDB, ctrlURL string) *Service {
	t.Helper()
	cfg := MockConfig(t)
	cfg.ZitiCtrlURL = ctrlURL
	zm := &ZitiManager{
		cfg:        cfg,
		logger:     zap.NewNop(),
		mgmtToken:  "test-token",
		mgmtClient: &http.Client{},
		mu:         sync.RWMutex{},
	}
	return &Service{db: db, logger: zap.NewNop(), zitiProvider: newZitiProviderWith(zm)}
}
