package tunnel

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeRules records what the manager asks the operating system to do.
type fakeRules struct {
	unsupported error
	applyErr    error
	clearErr    error
	applies     [][]string
	clears      [][]string
}

func (f *fakeRules) Supported() error { return f.unsupported }
func (f *fakeRules) Apply(names []string, server string) error {
	if server != NamesAddr {
		return errors.New("rules must point at the agent's resolver")
	}
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applies = append(f.applies, append([]string(nil), names...))
	return nil
}
func (f *fakeRules) Clear(restore []string) error {
	if f.clearErr != nil {
		return f.clearErr
	}
	f.clears = append(f.clears, append([]string(nil), restore...))
	return nil
}

type fakeCloser struct{ closed int }

func (c *fakeCloser) Close() error { c.closed++; return nil }

// namesHarness is a Names over fakes: the system resolver is the responder
// itself, which is what a working path looks like.
type namesHarness struct {
	n       *Names
	rules   *fakeRules
	closer  *fakeCloser
	listens int
	listenE error
	clock   time.Time
	// resolveFn, when set, replaces the system resolver (to break the path).
	resolveFn func(ctx context.Context, host string) ([]string, error)
}

func newHarness(t *testing.T, protect ...string) *namesHarness {
	t.Helper()
	h := &namesHarness{rules: &fakeRules{}, closer: &fakeCloser{}, clock: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	n := NewNames(zap.NewNop(), filepath.Join(t.TempDir(), "names.marker"), protect...)
	n.rules = h.rules
	n.now = func() time.Time { return h.clock }
	n.listen = func(*Responder) (io.Closer, error) {
		h.listens++
		if h.listenE != nil {
			return nil, h.listenE
		}
		return h.closer, nil
	}
	n.resolve = func(ctx context.Context, host string) ([]string, error) {
		if h.resolveFn != nil {
			return h.resolveFn(ctx, host)
		}
		resp := n.resp.Answer(query(1, host, dnsTypeA))
		if resp == nil || rcodeOf(resp) != rcodeOK || ancount(resp) != 1 {
			return nil, errors.New("no such host")
		}
		a := resp[len(resp)-4:]
		return []string{net4(a)}, nil
	}
	h.n = n
	return h
}

func net4(a []byte) string {
	return strings.Join([]string{itoa(a[0]), itoa(a[1]), itoa(a[2]), itoa(a[3])}, ".")
}
func itoa(b byte) string {
	const d = "0123456789"
	if b >= 100 {
		return string([]byte{d[b/100], d[(b/10)%10], d[b%10]})
	}
	if b >= 10 {
		return string([]byte{d[b/10], d[b%10]})
	}
	return string([]byte{d[b]})
}

var wikiPin = NamePin{Name: "wiki.corp.example", IP: "100.127.0.10", Service: "openidx-net-wiki"}
var hrPin = NamePin{Name: "hr.corp.example", IP: "100.127.0.11", Service: "openidx-net-hr"}

func TestNamesAnswersOnlyAfterProvingThePath(t *testing.T) {
	h := newHarness(t)
	h.n.SetWanted(true, []NamePin{wikiPin, hrPin})
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki", "openidx-net-hr"})

	if st := h.n.Status(); st.State != NamesActive || st.Pins != 2 {
		t.Fatalf("status = %+v", st)
	}
	// The probe rule alone first, then the real names with the probe kept.
	want := [][]string{{selfTestName}, {"hr.corp.example", "wiki.corp.example", selfTestName}}
	if !reflect.DeepEqual(h.rules.applies, want) {
		t.Fatalf("rules applied = %v, want %v", h.rules.applies, want)
	}
	if h.listens != 1 {
		t.Errorf("listened %d times", h.listens)
	}
	if _, err := os.Stat(h.n.marker); err != nil {
		t.Error("no marker file while rules are applied")
	}
	// The responder now answers the pins.
	if resp := h.n.resp.Answer(query(1, "wiki.corp.example", dnsTypeA)); resp == nil || ancount(resp) != 1 {
		t.Error("the pinned name is not answered")
	}
}

func TestNamesTouchesNothingWhenTheLocalPathIsBlocked(t *testing.T) {
	for name, fn := range map[string]func(context.Context, string) ([]string, error){
		"no answer":            func(context.Context, string) ([]string, error) { return nil, errors.New("timed out") },
		"someone else answers": func(context.Context, string) ([]string, error) { return []string{"203.0.113.9"}, nil },
	} {
		h := newHarness(t)
		h.resolveFn = fn
		h.n.SetWanted(true, []NamePin{wikiPin})
		h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
		st := h.n.Status()
		if st.State != NamesDegraded || st.Detail == "" {
			t.Errorf("%s: status = %+v", name, st)
		}
		// Only the probe was ever applied, and it was taken out again; the
		// tunneler's rules for the real names were never touched.
		for _, a := range h.rules.applies {
			if !reflect.DeepEqual(a, []string{selfTestName}) {
				t.Errorf("%s: the real names were applied before the path was proven: %v", name, a)
			}
		}
		if len(h.rules.clears) != 1 || len(h.rules.clears[0]) != 0 {
			t.Errorf("%s: clears = %v, want one with nothing to restore", name, h.rules.clears)
		}
		if h.closer.closed != 1 {
			t.Errorf("%s: the listener was not closed", name)
		}
		// It does not try again before the retry delay.
		before := len(h.rules.applies)
		h.clock = h.clock.Add(retryEvery / 2)
		h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
		if len(h.rules.applies) != before {
			t.Errorf("%s: retried before the delay", name)
		}
		h.resolveFn = nil
		h.clock = h.clock.Add(retryEvery)
		h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
		if h.n.Status().State != NamesActive {
			t.Errorf("%s: did not recover once the path worked: %+v", name, h.n.Status())
		}
	}
}

func TestNamesAnswersOnlyServicesTheTunnelerLists(t *testing.T) {
	h := newHarness(t)
	h.n.SetWanted(true, []NamePin{wikiPin, hrPin})
	// Only wiki's service is listed: hr is not answered (it keeps resolving the way it does today).
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	if st := h.n.Status(); st.State != NamesActive || st.Pins != 1 {
		t.Fatalf("status = %+v", st)
	}
	if resp := h.n.resp.Answer(query(1, "hr.corp.example", dnsTypeA)); rcodeOf(resp) != rcodeRefuse {
		t.Error("a name whose service is not listed is answered")
	}
	// Nothing listed: everything is taken out and the tunneler's rules for the names put back.
	h.n.reconcile(context.Background(), true, nil)
	if st := h.n.Status(); st.State != NamesOff || !strings.Contains(st.Detail, "no pinned service") {
		t.Fatalf("status = %+v", st)
	}
	last := h.rules.clears[len(h.rules.clears)-1]
	if !reflect.DeepEqual(last, []string{"wiki.corp.example"}) {
		t.Errorf("restored %v, want the one name that had been replaced", last)
	}
	// The service comes back: it is answered again.
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	if h.n.Status().State != NamesActive {
		t.Errorf("did not answer again: %+v", h.n.Status())
	}
}

func TestNamesStopsWhenTheTunnelGoesDownOrTheSettingGoesOff(t *testing.T) {
	h := newHarness(t)
	h.n.SetWanted(true, []NamePin{wikiPin})
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})

	// The tunnel is down: the tunneler removed its own rules, so none are put back.
	h.n.reconcile(context.Background(), false, nil)
	if got := h.rules.clears[len(h.rules.clears)-1]; len(got) != 0 {
		t.Errorf("with the tunnel down %v were restored; there is nothing to restore into", got)
	}
	if st := h.n.Status(); st.State != NamesOff || !strings.Contains(st.Detail, "not connected") {
		t.Errorf("status = %+v", st)
	}
	if _, err := os.Stat(h.n.marker); err == nil {
		t.Error("the marker file is still there after the rules were removed")
	}

	// Up again, then the setting goes off while the tunnel is up: the tunneler's rule comes back.
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	h.n.SetWanted(false, nil)
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	if got := h.rules.clears[len(h.rules.clears)-1]; !reflect.DeepEqual(got, []string{"wiki.corp.example"}) {
		t.Errorf("restored %v", got)
	}
	if st := h.n.Status(); st.State != NamesOff || st.Wanted {
		t.Errorf("status = %+v", st)
	}
	// Idle and off, it does nothing at all: no process is spawned every 15 seconds.
	calls := len(h.rules.clears) + len(h.rules.applies)
	for i := 0; i < 3; i++ {
		h.n.reconcile(context.Background(), true, nil)
	}
	if len(h.rules.clears)+len(h.rules.applies) != calls {
		t.Error("an idle manager keeps calling the rules")
	}
}

func TestNamesRefusesWhatItShouldNotAnswer(t *testing.T) {
	h := newHarness(t, "openidx.corp.example")
	h.n.SetWanted(true, []NamePin{
		wikiPin,
		{Name: "openidx.corp.example", IP: "100.127.0.20", Service: ""},         // the agent's own server
		{Name: "10.1.2.3", IP: "100.127.0.25"},                                  // an address, not a name
		{Name: "*.corp.example", IP: "100.127.0.21"},                            // a wildcard
		{Name: "a'; Remove-Item C:\\ -Recurse; '.example", IP: "100.127.0.22"},  // an injection attempt
		{Name: "bad-ip.corp.example", IP: "10.0.0.1"},                           // outside the pin pool
		{Name: "tunnel-range.corp.example", IP: "100.64.0.5"},                   // the tunneler's own range
		{Name: "junk.corp.example", IP: "not-an-ip"},                            // not an address
		{Name: "nosvc.corp.example", IP: "100.127.0.23", Service: "not-listed"}, // its service is not listed
		{Name: "noservice-field.corp.example", IP: "100.127.0.24", Service: ""}, // an older server: no service named, answered
	})
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	got := map[string]bool{}
	for _, a := range h.rules.applies {
		for _, n := range a {
			got[n] = true
		}
	}
	for _, ok := range []string{"wiki.corp.example", "noservice-field.corp.example"} {
		if !got[ok] {
			t.Errorf("%s was not answered", ok)
		}
	}
	for _, bad := range []string{"openidx.corp.example", "10.1.2.3", "*.corp.example", "bad-ip.corp.example", "tunnel-range.corp.example", "junk.corp.example", "nosvc.corp.example"} {
		if got[bad] {
			t.Errorf("%s was answered", bad)
		}
	}
	for n := range got {
		if strings.ContainsAny(n, "';\\ ") {
			t.Errorf("a name with a metacharacter reached the rules: %q", n)
		}
	}
}

func TestNamesReportsWhyItCannotWork(t *testing.T) {
	// A platform with no hook.
	h := newHarness(t)
	h.rules.unsupported = ErrNamesUnsupported
	h.n.SetWanted(true, []NamePin{wikiPin})
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	if st := h.n.Status(); st.State != NamesDegraded || !strings.Contains(st.Detail, "Windows") || h.listens != 0 {
		t.Errorf("unsupported: %+v, listens %d", st, h.listens)
	}
	// A port taken: nothing is applied.
	h = newHarness(t)
	h.listenE = errors.New("address already in use")
	h.n.SetWanted(true, []NamePin{wikiPin})
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	if st := h.n.Status(); st.State != NamesDegraded || !strings.Contains(st.Detail, "127.64.0.2:53") || len(h.rules.applies) != 0 {
		t.Errorf("listen failure: %+v, applies %v", st, h.rules.applies)
	}
	// The rules cannot be written.
	h = newHarness(t)
	h.rules.applyErr = errors.New("access denied")
	h.n.SetWanted(true, []NamePin{wikiPin})
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki"})
	if st := h.n.Status(); st.State != NamesDegraded || !strings.Contains(st.Detail, "access denied") {
		t.Errorf("apply failure: %+v", st)
	}
}

func TestNamesReappliesWhenTheSetOrTheTunnelersServicesChange(t *testing.T) {
	h := newHarness(t)
	svcs := []string{"openidx-net-wiki", "openidx-net-hr"}
	h.n.SetWanted(true, []NamePin{wikiPin})
	h.n.reconcile(context.Background(), true, svcs)
	applied := len(h.rules.applies)
	h.n.reconcile(context.Background(), true, svcs)
	if len(h.rules.applies) != applied {
		t.Error("an unchanged set was applied again")
	}
	// The tunneler rewrites its own rules when its services change: do ours again.
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki", "openidx-net-hr", "openidx-net-new"})
	if len(h.rules.applies) != applied+1 {
		t.Error("a change in the tunneler's services did not re-apply")
	}
	// A new pin.
	h.n.SetWanted(true, []NamePin{wikiPin, hrPin})
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki", "openidx-net-hr", "openidx-net-new"})
	if len(h.rules.applies) != applied+2 {
		t.Error("a new pin did not re-apply")
	}
	// And now and then regardless.
	h.clock = h.clock.Add(reapplyEvery + time.Second)
	h.n.reconcile(context.Background(), true, []string{"openidx-net-wiki", "openidx-net-hr", "openidx-net-new"})
	if len(h.rules.applies) != applied+3 {
		t.Error("the periodic re-apply did not happen")
	}
}

func TestNamesGivesUpIfThePathBreaksLater(t *testing.T) {
	h := newHarness(t)
	h.n.SetWanted(true, []NamePin{wikiPin})
	svcs := []string{"openidx-net-wiki"}
	h.n.reconcile(context.Background(), true, svcs)
	h.resolveFn = func(context.Context, string) ([]string, error) { return nil, errors.New("blocked") }
	h.clock = h.clock.Add(reverifyEvery + time.Second)
	h.n.reconcile(context.Background(), true, svcs)
	if st := h.n.Status(); st.State != NamesDegraded {
		t.Fatalf("status = %+v", st)
	}
	// The tunnel is still up, so the tunneler's rule for the name is put back.
	if got := h.rules.clears[len(h.rules.clears)-1]; !reflect.DeepEqual(got, []string{"wiki.corp.example"}) {
		t.Errorf("restored %v", got)
	}
}

func TestNamesRemovesWhatACrashLeft(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.n.marker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.n.cleanOrphans()
	if len(h.rules.clears) != 1 {
		t.Fatalf("clears = %v, want one", h.rules.clears)
	}
	if _, err := os.Stat(h.n.marker); err == nil {
		t.Error("the marker is still there")
	}
	// With no marker nothing runs at all.
	h.n.cleanOrphans()
	if len(h.rules.clears) != 1 {
		t.Error("an agent that never applied anything spawned a clean-up")
	}
}

func TestNameScriptsNeverCarryAnythingButNames(t *testing.T) {
	good, err := nrptApplyScript([]string{"wiki.corp.example", selfTestName}, NamesAddr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"'wiki.corp.example,openidx-selftest.invalid'.Split(',')", "$server='127.64.0.2'", "Added by openidx-agent", "Added by openidx.ziti-edge-tunnel", "Clear-DnsClientCache"} {
		if !strings.Contains(good, want) {
			t.Errorf("apply script lacks %q", want)
		}
	}
	for _, bad := range []string{"a'; calc; '.example", "x y.example", "*.example", "UPPER.example", "single", "-lead.example", "a..b", strings.Repeat("a", 64) + ".example", "a\n.example"} {
		if _, err := nrptApplyScript([]string{bad}, NamesAddr); err == nil {
			t.Errorf("apply script accepted %q", bad)
		}
		if _, err := nrptClearScript([]string{bad}, tunnelerDNS); err == nil {
			t.Errorf("clear script accepted %q", bad)
		}
	}
	clear, err := nrptClearScript([]string{"wiki.corp.example"}, tunnelerDNS)
	if err != nil || !strings.Contains(clear, "$tunnelerDns='100.64.0.2'") || !strings.Contains(clear, "openidx.ziti-edge-tunnel:") {
		t.Errorf("clear script = %v, %q", err, clear)
	}
}
