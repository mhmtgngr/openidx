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
		Users                int  `json:"users"`
		Applications         int  `json:"applications"`
		WouldDeny            int  `json:"would_deny"`
		IncompleteUsers      int  `json:"incomplete_users"`
		UsersEvaluated       int  `json:"users_evaluated"`
		UsersTotal           int  `json:"users_total"`
		UsersWithoutIdentity int  `json:"users_without_identity"`
		EvaluationComplete   bool `json:"evaluation_complete"`
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
					 "serviceRoles":["#openidx-es-dev"],"identityRoles":["#all"]}],
					"meta":{"pagination":{"limit":500,"offset":0,"totalCount":2}}}`))
			case containsPath(r, "services"):
				_, _ = w.Write([]byte(`{"data":[
					{"id":"s-live","name":"openidx-es-dev","roleAttributes":["openidx-es-dev"]}],
					"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}`))
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
		// The denominator: both users exist and both were evaluated, which is
		// what entitles this report to a clean headline.
		if got.Summary.UsersEvaluated != 2 || got.Summary.UsersTotal != 2 {
			t.Fatalf("users_evaluated/users_total = %d/%d, want 2/2",
				got.Summary.UsersEvaluated, got.Summary.UsersTotal)
		}
		if !got.Summary.EvaluationComplete {
			t.Fatal("live controller, every user evaluated, nothing skipped: " +
				"evaluation_complete must be true")
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

	// F2 / section 2. The user set comes from ziti_identities, so a user with
	// no identity is simply absent from it. They must show up in the
	// denominator and in users_without_identity — never folded silently into
	// either "safe" or "incomplete".
	//
	// The ruling: such a user has no Ziti reach, therefore no Ziti reach to
	// LOSE, so they do NOT block completeness. Every org on this deployment has
	// them (service accounts, disabled accounts, admins who never onboarded),
	// and a go/no-go that can never read clean is one operators learn to
	// ignore. Without this subtest the signal is permanently amber.
	t.Run("a user with no Ziti identity is surfaced, not counted incomplete", func(t *testing.T) {
		const carol = "11111111-0000-0000-0000-0000000000c1"
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'carol','carol@x.io')`,
			carol, reportOrg); err != nil {
			t.Fatalf("seed carol: %v", err)
		}
		defer func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, carol) }()

		srv := liveControllerServer(t)
		defer srv.Close()
		s := reportService(t, db, srv.URL)
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.ReachabilitySource != ReachabilityFromController {
			t.Fatalf("reachability_source = %q, want %q", got.ReachabilitySource, ReachabilityFromController)
		}
		if got.Summary.UsersTotal != 3 || got.Summary.UsersEvaluated != 2 {
			t.Fatalf("users_evaluated/users_total = %d/%d, want 2/3",
				got.Summary.UsersEvaluated, got.Summary.UsersTotal)
		}
		if got.Summary.UsersWithoutIdentity != 1 {
			t.Fatalf("users_without_identity = %d, want 1 (carol): the gap between evaluated "+
				"and total must be explained, not hidden", got.Summary.UsersWithoutIdentity)
		}
		if got.Summary.IncompleteUsers != 0 {
			t.Fatalf("incomplete_users = %d, want 0: carol has no Ziti reach and therefore "+
				"no Ziti reach to lose", got.Summary.IncompleteUsers)
		}
		if !got.Summary.EvaluationComplete {
			t.Fatal("an org whose only shortfall is users with no Ziti identity must be able " +
				"to read as complete — a permanently amber go/no-go gets ignored")
		}
	})

	// Section 1, the reviewer's exact probe. ziti_identities.user_id has only a
	// NON-unique index, and one identity per enrolled device is the normal
	// shape. Counting identity ROWS lets a two-device user cancel out a user
	// with none: evaluated == total, and the report claims to have covered
	// somebody it never looked at.
	t.Run("a two-device user does not cancel out a user with no identity", func(t *testing.T) {
		const ann = "11111111-0000-0000-0000-0000000000e1"
		const ben = "11111111-0000-0000-0000-0000000000e2"
		seedProbe := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'ann','ann@x.io')`,
				[]any{ann, reportOrg}},
			{`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'ben','ben@x.io')`,
				[]any{ben, reportOrg}},
			// ann's laptop and phone: two rows, one user.
			{`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled, attributes)
			  VALUES (gen_random_uuid(),$1,'z-ann-laptop','ann-laptop',$2,true,'["browzer-users"]'::jsonb)`,
				[]any{reportOrg, ann}},
			{`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled, attributes)
			  VALUES (gen_random_uuid(),$1,'z-ann-phone','ann-phone',$2,true,'["browzer-users"]'::jsonb)`,
				[]any{reportOrg, ann}},
			// ben has no identity at all.
		}
		for _, st := range seedProbe {
			if _, err := db.Pool.Exec(ctx, st.sql, st.args...); err != nil {
				t.Fatalf("seed probe: %v", err)
			}
		}
		defer func() {
			_, _ = db.Pool.Exec(ctx, `DELETE FROM ziti_identities WHERE user_id = $1`, ann)
			_, _ = db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, ann)
			_, _ = db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, ben)
		}()

		srv := liveControllerServer(t)
		defer srv.Close()
		s := reportService(t, db, srv.URL)
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		// alice + ann evaluated; bob evaluated too (he has an identity, it just
		// reaches nothing). ben is not evaluated. Row-counting would have said
		// 4 of 4 — ann twice, ben never — and reported no shortfall at all.
		if got.Summary.UsersTotal != 4 {
			t.Fatalf("users_total = %d, want 4 (alice, bob, ann, ben)", got.Summary.UsersTotal)
		}
		if got.Summary.UsersEvaluated != 3 {
			t.Fatalf("users_evaluated = %d, want 3: ann's two identity rows are ONE user, "+
				"and counting rows lets her cancel out ben, who was never evaluated",
				got.Summary.UsersEvaluated)
		}
		if got.Summary.UsersWithoutIdentity != 1 {
			t.Fatalf("users_without_identity = %d, want 1 (ben): the shortfall must be "+
				"named, not silently absorbed", got.Summary.UsersWithoutIdentity)
		}
		// ann's reach is the UNION of her two identities, counted once. A
		// per-row diff would emit the same would-deny entry twice and leave
		// would_deny disagreeing with users.
		annEntries := 0
		for _, e := range got.Entries {
			if e.UserID == ann {
				annEntries++
			}
		}
		if annEntries != 1 {
			t.Fatalf("ann has %d would-deny entries for one application, want 1: %+v",
				annEntries, got.Entries)
		}
		if got.Summary.WouldDeny != len(got.Entries) || got.Summary.Users > got.Summary.WouldDeny {
			t.Fatalf("summary users/would_deny = %d/%d disagree with %d entries",
				got.Summary.Users, got.Summary.WouldDeny, len(got.Entries))
		}
	})

	// Section 4. The identity query joins users, so a ziti_identities row
	// pointing at a user in ANOTHER org would put that user into the numerator
	// while the denominator — which filters users.org_id — excludes them. Same
	// masking mechanism as counting rows, narrower trigger.
	t.Run("a cross-org identity row does not inflate the numerator", func(t *testing.T) {
		const otherOrg = "00000000-0000-0000-0000-0000000000cc"
		const outsider = "11111111-0000-0000-0000-0000000000f1"
		seedCross := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'outsider','out@x.io')`,
				[]any{outsider, otherOrg}},
			// The identity row claims this org; the user does not belong to it.
			{`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled, attributes)
			  VALUES (gen_random_uuid(),$1,'z-outsider','outsider',$2,true,'["browzer-users"]'::jsonb)`,
				[]any{reportOrg, outsider}},
		}
		for _, st := range seedCross {
			if _, err := db.Pool.Exec(ctx, st.sql, st.args...); err != nil {
				t.Fatalf("seed cross-org: %v", err)
			}
		}
		defer func() {
			_, _ = db.Pool.Exec(ctx, `DELETE FROM ziti_identities WHERE user_id = $1`, outsider)
			_, _ = db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, outsider)
		}()

		srv := liveControllerServer(t)
		defer srv.Close()
		s := reportService(t, db, srv.URL)
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.Summary.UsersTotal != 2 || got.Summary.UsersEvaluated != 2 {
			t.Fatalf("users_evaluated/users_total = %d/%d, want 2/2: a user from another org "+
				"must not be evaluated against this org's denominator",
				got.Summary.UsersEvaluated, got.Summary.UsersTotal)
		}
		for _, e := range got.Entries {
			if e.UserID == outsider {
				t.Fatalf("another org's user leaked into the report: %+v", e)
			}
		}
	})

	// F2. Evaluating nobody is not the same answer as "nobody loses anything".
	t.Run("an org with no users reports a zero denominator, not a clean sweep", func(t *testing.T) {
		const emptyOrg = "00000000-0000-0000-0000-0000000000ee"
		srv := liveControllerServer(t)
		defer srv.Close()
		s := reportService(t, db, srv.URL)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/assignment-report", nil)
		c.Request = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: emptyOrg}))
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.Summary.UsersTotal != 0 || got.Summary.UsersEvaluated != 0 {
			t.Fatalf("users_evaluated/users_total = %d/%d, want 0/0",
				got.Summary.UsersEvaluated, got.Summary.UsersTotal)
		}
		if len(got.Entries) != 0 {
			t.Fatalf("an empty org has nothing to report, got %+v", got.Entries)
		}
		// Section 3. The go/no-go is computed here, once, so that a client
		// reading only `summary` cannot mistake would_deny:0 + incomplete:0 +
		// source:"controller" for a clean sweep over an evaluation of nobody.
		if got.Summary.EvaluationComplete {
			t.Fatal("evaluation_complete must be false when nobody was evaluated: an empty " +
				"evaluation is not evidence that enforcement is safe")
		}
	})

	// Section 2's other edge: an org whose sync has never run has users, but
	// every one of them lacks an identity. Nobody is evaluated, so it cannot
	// read as complete however clean the diff looks.
	t.Run("an org where every user lacks an identity does not read as complete", func(t *testing.T) {
		const syncOrg = "00000000-0000-0000-0000-0000000000df"
		const unsynced = "11111111-0000-0000-0000-0000000000f9"
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'unsynced','uns@x.io')`,
			unsynced, syncOrg); err != nil {
			t.Fatalf("seed unsynced: %v", err)
		}
		defer func() { _, _ = db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, unsynced) }()

		srv := liveControllerServer(t)
		defer srv.Close()
		s := reportService(t, db, srv.URL)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest(http.MethodGet, "/assignment-report", nil)
		c.Request = req.WithContext(orgctx.With(req.Context(), orgctx.Org{ID: syncOrg}))
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.Summary.UsersTotal != 1 || got.Summary.UsersWithoutIdentity != 1 {
			t.Fatalf("users_total/users_without_identity = %d/%d, want 1/1",
				got.Summary.UsersTotal, got.Summary.UsersWithoutIdentity)
		}
		if got.Summary.EvaluationComplete {
			t.Fatal("an org whose Ziti sync has never run evaluates nobody and must not " +
				"read as complete — this is the case users_evaluated > 0 exists to catch")
		}
	})

	// F1. A malformed attributes value would leave the identity matching fewer
	// policies than it really does — under-reported reach, i.e. a report that
	// fails toward "safe". The user must be counted, not silently scored.
	t.Run("a malformed attributes value counts the user as incomplete", func(t *testing.T) {
		const dave = "11111111-0000-0000-0000-0000000000d1"
		seedDave := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO users (id, org_id, username, email) VALUES ($1,$2,'dave','dave@x.io')`,
				[]any{dave, reportOrg}},
			{`INSERT INTO ziti_identities (id, org_id, ziti_id, name, user_id, enrolled, attributes)
			  VALUES (gen_random_uuid(),$1,'z-dave','dave',$2,true,'"not-an-array"'::jsonb)`,
				[]any{reportOrg, dave}},
		}
		for _, st := range seedDave {
			if _, err := db.Pool.Exec(ctx, st.sql, st.args...); err != nil {
				t.Fatalf("seed dave: %v", err)
			}
		}
		defer func() {
			_, _ = db.Pool.Exec(ctx, `DELETE FROM ziti_identities WHERE user_id = $1`, dave)
			_, _ = db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, dave)
		}()

		srv := liveControllerServer(t)
		defer srv.Close()
		s := reportService(t, db, srv.URL)
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.Summary.UsersEvaluated != 2 || got.Summary.UsersTotal != 3 {
			t.Fatalf("users_evaluated/users_total = %d/%d, want 2/3",
				got.Summary.UsersEvaluated, got.Summary.UsersTotal)
		}
		if got.Summary.IncompleteUsers != 1 {
			t.Fatalf("incomplete_users = %d, want 1 (dave's attributes could not be read)",
				got.Summary.IncompleteUsers)
		}
		// Dave HAS an identity — it just could not be read — so he is not a
		// without-identity user, and he does block completeness.
		if got.Summary.UsersWithoutIdentity != 0 {
			t.Fatalf("users_without_identity = %d, want 0: dave has an identity row",
				got.Summary.UsersWithoutIdentity)
		}
		if got.Summary.EvaluationComplete {
			t.Fatal("a user whose identity could not be read leaves the report incomplete")
		}
	})

	// F1. A row failure in the service→application index is not a per-user
	// problem: it removes an application from the reach side for EVERY user,
	// which is exactly the under-report this endpoint exists to remove. The
	// report must say "unavailable", not present a clean diff over what it
	// managed to read.
	t.Run("a failed application row makes the whole report unavailable", func(t *testing.T) {
		const badRoute = "33333333-0000-0000-0000-0000000000b2"
		const badApp = "22222222-0000-0000-0000-0000000000b2"
		setup := []struct {
			sql  string
			args []any
		}{
			{`ALTER TABLE applications ALTER COLUMN name DROP NOT NULL`, nil},
			{`INSERT INTO proxy_routes (id, name, ziti_enabled, ziti_service_name) VALUES ($1,'bad',true,'openidx-bad')`,
				[]any{badRoute}},
			{`INSERT INTO applications (id, org_id, name, route_id, enabled) VALUES ($1,$2,NULL,$3,true)`,
				[]any{badApp, reportOrg, badRoute}},
		}
		for _, st := range setup {
			if _, err := db.Pool.Exec(ctx, st.sql, st.args...); err != nil {
				t.Fatalf("seed %q: %v", st.sql, err)
			}
		}
		defer func() {
			_, _ = db.Pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, badApp)
			_, _ = db.Pool.Exec(ctx, `DELETE FROM proxy_routes WHERE id = $1`, badRoute)
			_, _ = db.Pool.Exec(ctx, `ALTER TABLE applications ALTER COLUMN name SET NOT NULL`)
		}()

		srv := liveControllerServer(t)
		defer srv.Close()
		s := reportService(t, db, srv.URL)
		c, w := newCtx()
		s.handleAssignmentReport(c)
		got := decode(t, w)

		if got.ReachabilitySource != ReachabilityUnavailable {
			t.Fatalf("reachability_source = %q, want %q: a row the report could not read "+
				"drops an application for every user and must not yield a clean report",
				got.ReachabilitySource, ReachabilityUnavailable)
		}
		if got.ReachabilityError == "" {
			t.Error("reachability_error must name the input failure")
		}
		if len(got.Entries) != 0 {
			t.Fatalf("a report built on partial inputs must not present a diff: %+v", got.Entries)
		}
	})
}

// liveControllerServer is the fake controller the passing subtests share: one
// Dial policy for #browzer-users over the `#openidx-es-dev` tag the reconciler
// actually emits, plus the meta.pagination block the paginating listers
// require before they will call a listing complete.
func liveControllerServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case containsPath(r, "service-policies"):
			_, _ = w.Write([]byte(`{"data":[
				{"id":"p1","name":"openidx-dial-openidx-es-dev","type":"Dial",
				 "serviceRoles":["#openidx-es-dev"],"identityRoles":["#browzer-users"]}],
				"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}`))
		case containsPath(r, "services"):
			_, _ = w.Write([]byte(`{"data":[
				{"id":"s-live","name":"openidx-es-dev","roleAttributes":["openidx-es-dev"]}],
				"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
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
