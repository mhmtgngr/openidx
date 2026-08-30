package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// These tests cover the paths that could still reach a clean "safe to enforce"
// verdict over data that was never fully gathered: an unchecked row iteration,
// a listing the controller truncated, and a policy filter that kept nothing.
// The governing rule throughout is that the report may only say "safe" when it
// actually evaluated everything, and anything less must say so loudly.

// ---------------------------------------------------------------------------
// F1 — the scan loops
// ---------------------------------------------------------------------------

// fakeRows is a scriptable reportRows: a list of row payloads, an optional
// per-row scan error, and an optional iteration error surfaced by Err() the
// way pgx surfaces a connection reset or a cancelled context mid-stream.
type fakeRows struct {
	rows     [][]any
	scanErrs map[int]error
	iterErr  error
	i        int
}

func (f *fakeRows) Next() bool {
	if f.i >= len(f.rows) {
		return false
	}
	f.i++
	return true
}

func (f *fakeRows) Err() error { return f.iterErr }

func (f *fakeRows) Scan(dest ...any) error {
	idx := f.i - 1
	if err, ok := f.scanErrs[idx]; ok {
		return err
	}
	row := f.rows[idx]
	if len(row) != len(dest) {
		return fmt.Errorf("fakeRows: row %d has %d values, scanned into %d", idx, len(row), len(dest))
	}
	for i, v := range row {
		switch d := dest[i].(type) {
		case *string:
			s, ok := v.(string)
			if !ok {
				return fmt.Errorf("fakeRows: value %d is not a string", i)
			}
			*d = s
		case *[]byte:
			b, ok := v.([]byte)
			if !ok {
				return fmt.Errorf("fakeRows: value %d is not []byte", i)
			}
			*d = b
		case *bool:
			b, ok := v.(bool)
			if !ok {
				return fmt.Errorf("fakeRows: value %d is not a bool", i)
			}
			*d = b
		default:
			return fmt.Errorf("fakeRows: unsupported destination %T", dest[i])
		}
	}
	return nil
}

func userRow(id, name, zitiID, attrs string) []any {
	return []any{id, name, zitiID, []byte(attrs)}
}

// TestScanReportUsersRowError: an iteration that aborts part-way leaves a
// PARTIAL user list. Reporting over it would say "source: controller,
// incomplete_users: 0" — a clean report built on users the query never
// delivered.
func TestScanReportUsersRowError(t *testing.T) {
	boom := errors.New("connection reset by peer")
	rows := &fakeRows{
		rows:    [][]any{userRow("u1", "alice", "z1", `["browzer-users"]`)},
		iterErr: boom,
	}
	users, names, incomplete, unidentified, err := scanReportUsers(rows)
	if err == nil {
		t.Fatal("a row-iteration failure must be reported: the user list is partial, " +
			"and diffing over a partial list is exactly how this report reaches a false \"safe\"")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error must carry the cause, got %v", err)
	}
	if users != nil || names != nil {
		t.Errorf("a failed iteration must not hand back the rows it did read: %v / %v", users, names)
	}
	_, _ = incomplete, unidentified
}

// TestScanReportUsersPerRowFailures: a row that cannot be scanned, and a row
// whose attributes are malformed, are both users the report did not evaluate.
// Neither may vanish silently — an unevaluated user counted as zero is
// indistinguishable from an evaluated user who loses nothing.
func TestScanReportUsersPerRowFailures(t *testing.T) {
	t.Run("scan failure", func(t *testing.T) {
		rows := &fakeRows{
			rows: [][]any{
				userRow("u1", "alice", "z1", `["browzer-users"]`),
				userRow("u2", "bob", "z2", `[]`),
			},
			scanErrs: map[int]error{1: errors.New("bad column type")},
		}
		users, _, incomplete, unidentified, err := scanReportUsers(rows)
		if err != nil {
			t.Fatalf("a single bad row is not a fatal input failure: %v", err)
		}
		if len(users) != 1 {
			t.Fatalf("want the one readable user, got %+v", users)
		}
		// The row could not be attributed to a user at all, so it cannot join
		// the incomplete SET — it is counted separately, and still counted.
		if unidentified != 1 || len(incomplete) != 0 {
			t.Fatalf("unidentified/incomplete = %d/%v, want 1/none: the skipped row must be counted",
				unidentified, incomplete)
		}
	})

	t.Run("malformed attributes", func(t *testing.T) {
		rows := &fakeRows{
			rows: [][]any{
				userRow("u1", "alice", "z1", `["browzer-users"]`),
				// Valid jsonb, but not the array the column is meant to hold.
				// Treating it as "no attributes" would match fewer policies,
				// i.e. under-report reach.
				userRow("u2", "bob", "z2", `"not-an-array"`),
			},
		}
		users, _, incomplete, unidentified, err := scanReportUsers(rows)
		if err != nil {
			t.Fatalf("unexpected fatal error: %v", err)
		}
		if len(users) != 1 || users[0].ID != "u1" {
			t.Fatalf("the user with unreadable attributes must be excluded, got %+v", users)
		}
		// The user id IS readable here, so the user joins the incomplete set
		// by id — which is what makes a second, readable identity row for the
		// same user unable to cancel this one out.
		if !incomplete["u2"] || len(incomplete) != 1 || unidentified != 0 {
			t.Fatalf("incomplete/unidentified = %v/%d, want {u2}/0", incomplete, unidentified)
		}
	})

	t.Run("a user's other identity does not cancel out an unreadable one", func(t *testing.T) {
		// Two enrolled devices, one of which has unreadable attributes. The
		// user's reach is partial either way, so they must still be counted
		// incomplete — the set does that; a counter would have been offset by
		// the good row's evaluation.
		rows := &fakeRows{
			rows: [][]any{
				userRow("u1", "alice", "z-laptop", `"not-an-array"`),
				userRow("u1", "alice", "z-phone", `["browzer-users"]`),
			},
		}
		users, _, incomplete, _, err := scanReportUsers(rows)
		if err != nil {
			t.Fatalf("unexpected fatal error: %v", err)
		}
		if len(users) != 1 || users[0].ZitiID != "z-phone" {
			t.Fatalf("the readable identity must still be returned, got %+v", users)
		}
		if !incomplete["u1"] {
			t.Fatal("a user with one unreadable identity has partial reach and must be " +
				"counted incomplete even though another identity read cleanly")
		}
	})
}

// TestScanServiceAppsFailuresAreFatal: a dropped service→application row
// removes that application from the reach side for EVERY user, so it is an
// input failure, not one incomplete user.
func TestScanServiceAppsFailuresAreFatal(t *testing.T) {
	t.Run("iteration error", func(t *testing.T) {
		rows := &fakeRows{
			rows:    [][]any{{"svc-a", "app-a", "App A"}},
			iterErr: errors.New("context canceled"),
		}
		if _, err := scanServiceApps(rows); err == nil {
			t.Fatal("a truncated application index under-reports reach for every user " +
				"and must not yield a usable index")
		}
	})

	t.Run("scan error", func(t *testing.T) {
		rows := &fakeRows{
			rows:     [][]any{{"svc-a", "app-a", "App A"}, {"svc-b", "app-b", "App B"}},
			scanErrs: map[int]error{1: errors.New("cannot scan NULL into *string")},
		}
		if _, err := scanServiceApps(rows); err == nil {
			t.Fatal("a dropped application row must not be swallowed")
		}
	})

	t.Run("clean read", func(t *testing.T) {
		rows := &fakeRows{rows: [][]any{{"svc-a", "app-a", "App A"}}}
		got, err := scanServiceApps(rows)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref, ok := got["svc-a"]; !ok || ref.ID != "app-a" || ref.Name != "App A" {
			t.Fatalf("index = %+v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// F3 — real pagination, not a len() >= limit guess
// ---------------------------------------------------------------------------

// zitiManagerFor builds a ZitiManager pointed at a fake controller. No DB.
func zitiManagerFor(t *testing.T, ctrlURL string) *ZitiManager {
	t.Helper()
	cfg := MockConfig(t)
	cfg.ZitiCtrlURL = ctrlURL
	return &ZitiManager{
		cfg:        cfg,
		logger:     zap.NewNop(),
		mgmtToken:  "test-token",
		mgmtClient: &http.Client{},
		mu:         sync.RWMutex{},
	}
}

// TestListAllPagesEveryRecord: the controller is free to cap `limit`
// server-side below what we asked for — OpenZiti versions have done exactly
// that — so the helper must follow meta.pagination.totalCount rather than
// assume the first page is everything. Here the fake honours a limit of 2
// against a limit=500 request, which is precisely the case the old
// `len(...) >= 1000` heuristic could never detect.
func TestListAllPagesEveryRecord(t *testing.T) {
	const total = 5
	var requested []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		requested = append(requested, offset)
		const serverCap = 2 // the controller ignores our limit=500
		body := `{"data":[`
		n := 0
		for i := offset; i < total && n < serverCap; i, n = i+1, n+1 {
			if n > 0 {
				body += ","
			}
			body += fmt.Sprintf(`{"id":"s%d","name":"svc-%d"}`, i, i)
		}
		body += fmt.Sprintf(`],"meta":{"pagination":{"limit":%d,"offset":%d,"totalCount":%d}}}`,
			serverCap, offset, total)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := zitiManagerFor(t, srv.URL).ListAllServices(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != total {
		t.Fatalf("got %d services, want %d — a short listing under-reports reach", len(got), total)
	}
	for i, svc := range got {
		if svc.Name != fmt.Sprintf("svc-%d", i) {
			t.Fatalf("service %d = %q, want svc-%d", i, svc.Name, i)
		}
	}
	// 0, 2, 4 — the loop follows what the controller actually returned, and
	// terminates once len(out) reaches totalCount.
	if len(requested) != 3 {
		t.Fatalf("offsets requested = %v, want three pages", requested)
	}
}

// TestListAllWithoutPaginationIsAnError: no meta.pagination means completeness
// is unknowable. Assuming the page is everything is the failure direction that
// reads as "safe to enforce".
func TestListAllWithoutPaginationIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"p1","name":"dial","type":"Dial"}]}`))
	}))
	defer srv.Close()

	if _, err := zitiManagerFor(t, srv.URL).ListAllServicePolicies(context.Background()); err == nil {
		t.Fatal("a response without meta.pagination cannot be shown to be complete " +
			"and must not be accepted as a full listing")
	}
}

// TestListAllStopsOnAnEmptyPage: a controller that claims more records than it
// will hand over cannot be paged to completion. The loop must terminate with
// an error rather than spin or silently return a short list.
func TestListAllStopsOnAnEmptyPage(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		w.Header().Set("Content-Type", "application/json")
		if offset == 0 {
			_, _ = w.Write([]byte(`{"data":[{"id":"s0","name":"svc-0"}],
				"meta":{"pagination":{"limit":1,"offset":0,"totalCount":9}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{"limit":1,"offset":1,"totalCount":9}}}`))
	}))
	defer srv.Close()

	if _, err := zitiManagerFor(t, srv.URL).ListAllServices(context.Background()); err == nil {
		t.Fatal("paging that cannot make progress must be an error, not a short listing")
	}
	if calls != 2 {
		t.Fatalf("controller called %d times, want 2 — the loop must terminate immediately", calls)
	}
}

// ---------------------------------------------------------------------------
// F4 — policies present, none of them Dial
// ---------------------------------------------------------------------------

// TestReachabilityInputsRejectsNoDialPolicies: if the controller's `type`
// field goes absent or gets renamed, the Dial filter keeps nothing, every user
// reaches nothing, and the report says "controller / incomplete_users: 0" —
// the cleanest possible false "safe". On a live overlay every published route
// has a Dial policy, so "policies exist but none is Dial" is a signal that the
// filter, not the overlay, is wrong.
func TestReachabilityInputsRejectsNoDialPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case containsPath(r, "service-policies"):
			_, _ = w.Write([]byte(`{"data":[
				{"id":"p1","name":"openidx-dial-openidx-es-dev",
				 "serviceRoles":["#openidx-es-dev"],"identityRoles":["#browzer-users"]}],
				"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}`))
		case containsPath(r, "services"):
			_, _ = w.Write([]byte(`{"data":[{"id":"s1","name":"openidx-es-dev"}],
				"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, _, err := reachabilityInputs(context.Background(), zitiManagerFor(t, srv.URL))
	if err == nil {
		t.Fatal("policies returned but none of type Dial is not a credible " +
			"\"nobody may dial anything\" — it must be reported as unavailable")
	}
}

// TestReachabilityInputsAcceptsAnEmptyController: an overlay with no policies
// at all IS a legitimate answer, and must not be confused with the case above.
func TestReachabilityInputsAcceptsAnEmptyController(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":0}}}`))
	}))
	defer srv.Close()

	dial, _, err := reachabilityInputs(context.Background(), zitiManagerFor(t, srv.URL))
	if err != nil {
		t.Fatalf("an empty controller is a real answer, not a failure: %v", err)
	}
	if len(dial) != 0 {
		t.Fatalf("want no dial policies, got %+v", dial)
	}
}

// ---------------------------------------------------------------------------
// F5 — a #tag that names a service
// ---------------------------------------------------------------------------

// TestServiceTagResolvesByName: the reconciler's ensureServiceAttr normally
// gives a service its own name as a role attribute, so `#openidx-foo` resolves
// through byAttr. A service that predates it — or one created by hand — has no
// such attribute, and the role would degrade to the literal "#openidx-foo",
// match no application, and drop out of reach. The name index closes that.
func TestServiceTagResolvesByName(t *testing.T) {
	idx := zitiServiceIndex{
		byZitiID: map[string]string{"s1": "openidx-es-dev"},
		all:      []string{"openidx-es-dev"},
		byAttr:   map[string][]string{}, // the service carries no role attributes
		byName:   map[string]bool{"openidx-es-dev": true},
	}
	_, got := reachabilityForIdentity(
		[]zitiDialPolicy{{Name: "openidx-dial-openidx-es-dev",
			IdentityRoles: []string{"#all"}, ServiceRoles: []string{"#openidx-es-dev"}}},
		"z1", nil, idx)
	if len(got) != 1 || got[0] != "openidx-es-dev" {
		t.Fatalf("a #tag naming a service must resolve to that service, got %v", got)
	}

	// A tag that names nothing at all still surfaces as the raw role, so the
	// intent stays visible — unchanged behaviour.
	if _, unknown := reachabilityForIdentity(
		[]zitiDialPolicy{{Name: "p", IdentityRoles: []string{"#all"}, ServiceRoles: []string{"#nothing"}}},
		"z1", nil, idx); len(unknown) != 1 || unknown[0] != "#nothing" {
		t.Fatalf("an unresolvable tag must still surface as intent, got %v", unknown)
	}
}

// TestServiceNameIndexLeavesTheMirrorPathAlone: the mirror path passes a nil
// byAttr AND a nil byName. Both index lookups must therefore be no-ops there,
// which is what keeps the mirror-backed access map byte-for-byte what it was.
func TestServiceNameIndexLeavesTheMirrorPathAlone(t *testing.T) {
	mirror := zitiServiceIndex{
		byZitiID: map[string]string{"s1": "prod-db"},
		all:      []string{"prod-db"},
		// byAttr and byName deliberately nil, as collectZitiPillar leaves them
	}
	got := resolveServiceRolesIndexed([]string{"#prod-db", "#web-apps", "@s1"}, mirror)
	want := []string{"#prod-db", "#web-apps", "prod-db"}
	if len(got) != len(want) {
		t.Fatalf("mirror resolution = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mirror resolution = %v, want %v — the name index must not reach the mirror path",
				got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// F2 / F4 - the denominator explains itself
// ---------------------------------------------------------------------------

// TestScanOrgUsersListAndCountCannotDisagree: the page asks the operator to
// "check that none of them should have been enrolled", so the identity-less
// users are LISTED. The count the summary reports is the length of that list -
// one source, so a stale count can never contradict the rows on screen.
func TestScanOrgUsersListAndCountCannotDisagree(t *testing.T) {
	rows := &fakeRows{rows: [][]any{
		{"u1", "alice", false},
		{"u2", "svc-backup", true},
		{"u3", "carol@x.io", true},
	}}

	total, without, err := scanOrgUsers(rows)
	if err != nil {
		t.Fatalf("scanOrgUsers: %v", err)
	}
	if total != 3 {
		t.Fatalf("users_total = %d, want 3", total)
	}
	if len(without) != 2 {
		t.Fatalf("identity-less users = %+v, want 2", without)
	}
	if without[0].UserID != "u2" || without[0].Username != "svc-backup" {
		t.Errorf("first identity-less user = %+v, want u2/svc-backup", without[0])
	}
	if without[1].UserID != "u3" || without[1].Username != "carol@x.io" {
		t.Errorf("second identity-less user = %+v, want u3/carol@x.io", without[1])
	}
}

// TestScanOrgUsersFailureIsFatal: a dropped user row shrinks the denominator,
// which makes the report look like it covered MORE of the organization than it
// did - the same direction toward a false "safe to enforce" that every other
// failure path in this file refuses.
func TestScanOrgUsersFailureIsFatal(t *testing.T) {
	boom := errors.New("connection reset by peer")

	t.Run("per-row scan failure", func(t *testing.T) {
		rows := &fakeRows{
			rows:     [][]any{{"u1", "alice", false}, {"u2", "bob", true}},
			scanErrs: map[int]error{1: boom},
		}
		total, without, err := scanOrgUsers(rows)
		if err == nil {
			t.Fatal("a user row that could not be read must fail the denominator, " +
				"not silently shrink it")
		}
		if !errors.Is(err, boom) {
			t.Errorf("error must carry the cause, got %v", err)
		}
		if total != 0 || without != nil {
			t.Errorf("a failed read must not hand back a partial denominator: %d / %+v", total, without)
		}
	})

	t.Run("iteration failure", func(t *testing.T) {
		rows := &fakeRows{rows: [][]any{{"u1", "alice", false}}, iterErr: boom}
		total, without, err := scanOrgUsers(rows)
		if err == nil {
			t.Fatal("an aborted iteration leaves a partial user list and must be reported")
		}
		if total != 0 || without != nil {
			t.Errorf("a failed iteration must not hand back what it did read: %d / %+v", total, without)
		}
	})
}

// TestSummaryExplainsItselfWithoutTheTopLevel: a client reading only `summary`
// used to see evaluation_complete:false beside incomplete_users:0 and
// users_evaluated:5 with no way to explain it - reachability_source lived at the
// top level. The reason travels with the summary now, and is empty exactly when
// the report is complete.
func TestSummaryExplainsItselfWithoutTheTopLevel(t *testing.T) {
	cases := []struct {
		name       string
		source     string
		incomplete int
		evaluated  int
		wantReason string
	}{
		{"controller unreadable", ReachabilityUnavailable, 5, 0, "reachability_unavailable"},
		{"some users skipped", ReachabilityFromController, 2, 5, "users_incomplete"},
		{"nobody evaluated", ReachabilityFromController, 0, 0, "no_users_evaluated"},
		{"complete", ReachabilityFromController, 0, 5, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, summary := buildReport(map[string][]string{}, map[string][]string{},
				map[string]string{}, map[string]string{}, reportCounts{
					IncompleteUsers:    tc.incomplete,
					UsersEvaluated:     tc.evaluated,
					UsersTotal:         5,
					ReachabilitySource: tc.source,
					EvaluationComplete: evaluationComplete(tc.source, tc.incomplete, tc.evaluated),
					IncompleteReason:   incompleteReason(tc.source, tc.incomplete, tc.evaluated),
				})

			if got := summary["incomplete_reason"]; got != tc.wantReason {
				t.Errorf("summary incomplete_reason = %v, want %q", got, tc.wantReason)
			}
			if got := summary["reachability_source"]; got != tc.source {
				t.Errorf("summary reachability_source = %v, want %q", got, tc.source)
			}
			complete := summary["evaluation_complete"] == true
			if complete != (tc.wantReason == "") {
				t.Errorf("incomplete_reason %q disagrees with evaluation_complete %v: "+
					"a client cannot trust one against the other", tc.wantReason, complete)
			}
		})
	}
}

// TestSummaryCarriesTheUnmeasuredRouteCount: the reach half models the OVERLAY.
// ACCESS_ASSIGNMENT_ENFORCE also gates the reverse proxy for every
// application-backed route, so the summary must carry how many of those the
// report did not look at - otherwise a green headline speaks for a surface it
// never measured.
func TestSummaryCarriesTheUnmeasuredRouteCount(t *testing.T) {
	_, summary := buildReport(map[string][]string{}, map[string][]string{},
		map[string]string{}, map[string]string{}, reportCounts{
			UsersEvaluated:          5,
			UsersTotal:              5,
			RoutesOutsideReachModel: 4,
			ReachabilitySource:      ReachabilityFromController,
			EvaluationComplete:      true,
		})
	if got := summary["routes_outside_reach_model"]; got != 4 {
		t.Errorf("summary routes_outside_reach_model = %v, want 4", got)
	}
}
