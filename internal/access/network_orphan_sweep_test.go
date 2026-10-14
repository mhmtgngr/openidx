package access

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

const (
	orphanAppKeep = "1111aaaa-1111-4111-8111-111111111111"
	orphanAppGone = "3333cccc-3333-4333-8333-333333333333"
	orphanAppMore = "4444dddd-4444-4444-8444-444444444444"
)

type orphanSweepHarness struct {
	f      *fakeNetCtrl
	zm     *ZitiManager
	rec    *ZitiReconciler
	refs   map[string]networkAppRef
	mu     sync.Mutex
	audits []networkOrphanObject
}

// newOrphanSweepHarness converges a network service for each app on the fake
// controller, stamped two hours ago, and answers the database read from refs.
func newOrphanSweepHarness(t *testing.T, apps ...string) *orphanSweepHarness {
	t.Helper()
	pinTargetGuard(t)
	h := &orphanSweepHarness{f: newFakeNetCtrl(), refs: map[string]networkAppRef{}}
	created := time.Now().Add(-2 * time.Hour)
	h.f.now = func() time.Time { return created }
	h.zm = newNetTestManager(t, h.f)
	h.rec = &ZitiReconciler{logger: zap.NewNop(), status: map[string]string{}}
	h.rec.loadNetworkRefs = func(_ context.Context, ids []string) (map[string]networkAppRef, error) {
		out := map[string]networkAppRef{}
		for _, id := range ids {
			if r, ok := h.refs[id]; ok {
				out[id] = r
			}
		}
		return out, nil
	}
	h.rec.auditOrphan = func(_ context.Context, o networkOrphanObject, _ networkAppRef) {
		h.mu.Lock()
		h.audits = append(h.audits, o)
		h.mu.Unlock()
	}
	for _, app := range apps {
		tgt, err := normalizeNetworkTarget(NetworkTarget{Hosts: []string{"10.0.0.1"}})
		if err != nil {
			t.Fatal(err)
		}
		d := DesiredNetworkService{ApplicationID: app, OrgID: "org-1", ServiceName: networkServiceName(app), Target: tgt}
		if err := h.rec.ensureNetworkService(context.Background(), h.zm, d); err != nil {
			t.Fatalf("ensure %s: %v", app, err)
		}
	}
	return h
}

// dropService removes an app's service only, the way a prune whose config
// and policy deletes failed leaves the controller.
func (h *orphanSweepHarness) dropService(app string) {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	for id, s := range h.f.services {
		if s["name"] == networkServiceName(app) {
			delete(h.f.services, id)
		}
	}
}

// names lists every object name on the fake controller that mentions s.
func (h *orphanSweepHarness) names(s string) []string {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	var out []string
	for _, m := range []map[string]map[string]interface{}{h.f.configs, h.f.services, h.f.policies, h.f.serps} {
		for _, o := range m {
			if n, _ := o["name"].(string); strings.Contains(n, s) {
				out = append(out, n)
			}
		}
	}
	return out
}

// addForeign plants objects that look like the reconciler's and are not.
func (h *orphanSweepHarness) addForeign(t *testing.T) []string {
	t.Helper()
	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	add := func(m map[string]map[string]interface{}, id string, o map[string]interface{}) {
		o["id"], o["createdAt"] = id, old
		m[id] = o
	}
	gone := networkServiceName(orphanAppGone)
	// Right name, wrong config type: not what the reconciler writes.
	add(h.f.configs, "f1", map[string]interface{}{"name": networkServiceName(orphanAppMore) + "-intercept", "configTypeId": "host-type"})
	// Not a canonical UUID.
	add(h.f.configs, "f2", map[string]interface{}{"name": "openidx-net-not-a-uuid-host", "configTypeId": "host-type"})
	add(h.f.configs, "f3", map[string]interface{}{"name": networkServicePrefix + strings.ToUpper(orphanAppMore) + "-host", "configTypeId": "host-type"})
	// Someone else's config entirely.
	add(h.f.configs, "f4", map[string]interface{}{"name": "corp-intercept", "configTypeId": "intercept-type"})
	// Service of the right name without the openidx-managed marker.
	add(h.f.services, "f5", map[string]interface{}{"name": networkServiceName(orphanAppMore), "roleAttributes": []interface{}{"corp"}})
	// Policies close to ours.
	add(h.f.policies, "f6", map[string]interface{}{"name": "openidx-dial-corp", "type": "Dial"})
	add(h.f.policies, "f7", map[string]interface{}{"name": "corp-dial-" + gone, "type": "Dial"})
	return []string{"f1", "f2", "f3", "f4", "f5", "f6", "f7"}
}

func enforceCfg() NetworkOrphanSweepConfig {
	return NetworkOrphanSweepConfig{Mode: orphanSweepEnforce, Grace: 30 * time.Minute, MaxDeletes: 100}
}

func TestOrphanSweepObserveDeletesNothing(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppKeep, orphanAppGone)
	h.refs[orphanAppKeep] = networkAppRef{OrgID: "org-1", Owns: true}
	h.dropService(orphanAppGone)
	before := h.f.writeCount()

	cfg := enforceCfg()
	cfg.Mode = orphanSweepObserve
	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if h.f.writeCount() != before {
		t.Errorf("observe wrote to the controller: %v", h.f.writes[before:])
	}
	// 2 configs + bind + dial + serp of the gone app.
	if rep.WouldDelete != 5 || rep.Deleted != 0 || rep.OrphanApps != 1 {
		t.Errorf("report = %+v", rep)
	}
	if len(h.audits) != 0 {
		t.Errorf("observe audited deletions: %v", h.audits)
	}
}

func TestOrphanSweepEnforceRemovesOnlyProvablyOrphanedObjects(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppKeep, orphanAppGone)
	h.refs[orphanAppKeep] = networkAppRef{OrgID: "org-1", Owns: true}
	// The gone app's row still exists but no longer owns a network service.
	h.refs[orphanAppGone] = networkAppRef{OrgID: "org-2", Owns: false}
	h.dropService(orphanAppGone)
	foreign := h.addForeign(t)
	keepBefore := len(h.names(orphanAppKeep))

	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if left := h.names(networkServiceName(orphanAppGone)); len(left) != 0 {
		// f7 mentions the gone service but is not ours; filter it.
		for _, n := range left {
			if !strings.HasPrefix(n, "corp-") {
				t.Errorf("orphan %s survived", n)
			}
		}
	}
	if got := len(h.names(orphanAppKeep)); got != keepBefore {
		t.Errorf("owned app objects: %d before, %d after", keepBefore, got)
	}
	h.f.mu.Lock()
	for _, id := range foreign {
		_, c := h.f.configs[id]
		_, s := h.f.services[id]
		_, p := h.f.policies[id]
		if !c && !s && !p {
			t.Errorf("foreign object %s was deleted", id)
		}
	}
	h.f.mu.Unlock()
	if rep.Deleted != 5 || rep.DeleteFailed != 0 || len(h.audits) != 5 {
		t.Errorf("report = %+v, audits = %d", rep, len(h.audits))
	}
	// Policies go before configs.
	if len(h.audits) == 5 && (h.audits[0].Collection != "service-policies" || h.audits[4].Collection != "configs") {
		t.Errorf("delete order = %v", h.audits)
	}

	// A second run finds nothing more.
	rep, err = h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now())
	if err != nil || rep.Deleted != 0 || rep.OrphanApps != 0 {
		t.Errorf("second run = %+v, %v", rep, err)
	}
}

func TestOrphanSweepRemovesAWholeUnownedServiceToo(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppGone) // no ref at all: row deleted
	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if left := h.names(orphanAppGone); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	if rep.Deleted != 6 {
		t.Errorf("report = %+v", rep)
	}
}

func TestOrphanSweepKeepsAnOwnedAppWhoseServiceIsMissing(t *testing.T) {
	// The reconciler recreates the service; the sweep must not take the
	// configs out from under it.
	h := newOrphanSweepHarness(t, orphanAppKeep)
	h.refs[orphanAppKeep] = networkAppRef{OrgID: "org-1", Owns: true}
	h.dropService(orphanAppKeep)
	before := h.f.writeCount()
	if _, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if h.f.writeCount() != before {
		t.Errorf("wrote %v", h.f.writes[before:])
	}
}

func TestOrphanSweepGracePeriodLeavesYoungApplications(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppGone)
	h.dropService(orphanAppGone)
	// One object is fresh: the whole application waits.
	h.f.mu.Lock()
	for _, c := range h.f.configs {
		c["createdAt"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		break
	}
	h.f.mu.Unlock()
	before := h.f.writeCount()
	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if h.f.writeCount() != before || rep.InGrace != 5 || rep.Deleted != 0 {
		t.Errorf("report = %+v, writes %v", rep, h.f.writes[before:])
	}
	// Past the grace it goes.
	rep, err = h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now().Add(time.Hour))
	if err != nil || rep.Deleted != 5 {
		t.Errorf("after grace = %+v, %v", rep, err)
	}
}

func TestOrphanSweepMissingCreatedAtIsNotProvablyOld(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppGone)
	h.f.mu.Lock()
	for _, p := range h.f.policies {
		delete(p, "createdAt")
	}
	h.f.mu.Unlock()
	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now())
	if err != nil || rep.Deleted != 0 || rep.InGrace == 0 {
		t.Errorf("report = %+v, %v", rep, err)
	}
}

func TestOrphanSweepHonoursTheDeleteCap(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppGone, orphanAppMore)
	cfg := enforceCfg()
	cfg.MaxDeletes = 4
	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Deleted != 4 || rep.OverCap != 8 {
		t.Errorf("report = %+v", rep)
	}
	// Later runs finish the backlog.
	for i := 0; i < 3; i++ {
		if _, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, cfg, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if left := append(h.names(orphanAppGone), h.names(orphanAppMore)...); len(left) != 0 {
		t.Errorf("left behind after the backlog drained: %v", left)
	}
}

func TestOrphanSweepAbandonsTheRunWhenTheDatabaseCannotBeRead(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppGone)
	h.rec.loadNetworkRefs = func(context.Context, []string) (map[string]networkAppRef, error) {
		return nil, errors.New("db down")
	}
	before := h.f.writeCount()
	if _, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now()); err == nil {
		t.Error("expected the run to be abandoned")
	}
	if h.f.writeCount() != before {
		t.Errorf("wrote %v", h.f.writes[before:])
	}
}

func TestOrphanSweepStopsAnApplicationAtTheFirstRefusedDelete(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppGone)
	h.f.failDeletes = map[string]bool{"services": true}
	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm, enforceCfg(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Both policies and the serp went; the service refused; the configs it still
	// references were not attempted.
	if rep.DeleteFailed != 1 || rep.Deleted != 3 {
		t.Errorf("report = %+v", rep)
	}
	h.f.mu.Lock()
	n := len(h.f.configs)
	h.f.mu.Unlock()
	if n != 2 {
		t.Errorf("configs left = %d, want 2", n)
	}
}

func TestOrphanSweepOffDoesNothing(t *testing.T) {
	h := newOrphanSweepHarness(t, orphanAppGone)
	before := h.f.writeCount()
	rep, err := h.rec.sweepNetworkOrphans(context.Background(), h.zm,
		NetworkOrphanSweepConfig{Mode: orphanSweepOff, MaxDeletes: 10}, time.Now())
	if err != nil || rep.Candidates != 0 || h.f.writeCount() != before {
		t.Errorf("off: %+v, %v", rep, err)
	}
}

func TestNetworkAppIDFromServiceNameIsStrict(t *testing.T) {
	for name, want := range map[string]bool{
		networkServiceName(orphanAppGone):                                 true,
		networkServicePrefix + strings.ToUpper(orphanAppGone):             false,
		networkServicePrefix + "{" + orphanAppGone + "}":                  false,
		networkServicePrefix + orphanAppGone + "-x":                       false,
		networkServicePrefix + strings.ReplaceAll(orphanAppGone, "-", ""): false,
		"openidx-" + orphanAppGone:                                        false,
		"":                                                                false,
	} {
		if _, ok := networkAppIDFromServiceName(name); ok != want {
			t.Errorf("%q: got %v, want %v", name, ok, want)
		}
	}
}

func TestNetworkOrphanSweepConfigFromEnv(t *testing.T) {
	for _, tc := range []struct {
		mode, grace, max string
		want             NetworkOrphanSweepConfig
	}{
		{"", "", "", NetworkOrphanSweepConfig{Mode: orphanSweepObserve, Grace: 30 * time.Minute, MaxDeletes: 20}},
		{"enforce", "60", "5", NetworkOrphanSweepConfig{Mode: orphanSweepEnforce, Grace: time.Hour, MaxDeletes: 5}},
		{"OFF", "1", "100000", NetworkOrphanSweepConfig{Mode: orphanSweepOff, Grace: orphanSweepMinGrace, MaxDeletes: orphanSweepMaxMaxDeletes}},
		{"enforec", "x", "-3", NetworkOrphanSweepConfig{Mode: orphanSweepObserve, Grace: 30 * time.Minute, MaxDeletes: 20}},
	} {
		t.Setenv("ZITI_ORPHAN_SWEEP", tc.mode)
		t.Setenv("ZITI_ORPHAN_SWEEP_GRACE_MINUTES", tc.grace)
		t.Setenv("ZITI_ORPHAN_SWEEP_MAX_DELETES", tc.max)
		got := NetworkOrphanSweepConfigFromEnv()
		got.Interval = 0
		if got != tc.want {
			t.Errorf("%q/%q/%q: got %+v, want %+v", tc.mode, tc.grace, tc.max, got, tc.want)
		}
	}
}
