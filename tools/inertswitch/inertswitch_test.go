package main

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/openidx/openidx/tools/racecost"
)

// TestTheFixtureTellsTheShapesApart is the gate's own subject: a request struct
// with one switch of each shape. It runs the real analysis over testdata, so it
// exercises the loader, the binder detection, the transfer edges and the
// decision classifier — and it costs one small package rather than the module.
func TestTheFixtureTellsTheShapesApart(t *testing.T) {
	switches, decided, excused, err := analyze([]string{"./testdata/switchfixture"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	var keys []string
	for _, s := range switches {
		keys = append(keys, s.Key)
	}
	sort.Strings(keys)
	want := []string{
		"switchfixture.Request.Decided",
		"switchfixture.Request.Inert",
		"switchfixture.Request.Transferred",
	}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("census = %v, want %v. Request is the only bound struct and NotABool is not a "+
			"bool, so those three are the whole settable set.", keys, want)
	}

	state := map[string]bool{}
	for _, s := range switches {
		state[s.Key] = decided[s.Decl] || excused[s.Decl]
	}

	if !state["switchfixture.Request.Decided"] {
		t.Error("Decided is the subject of an if and was reported inert. A census that cannot " +
			"see a plain condition would report every switch in the tree.")
	}
	if !state["switchfixture.Request.Transferred"] {
		t.Error("Transferred is copied into Model.Kept, which is compared, and was reported " +
			"inert. Nearly every request field is copied into a model before it reaches SQL, so " +
			"without that edge this gate fails everything and means nothing.")
	}
	if state["switchfixture.Request.Inert"] {
		t.Error("Inert is bound, copied and stored, and nothing ever tests it — which is exactly " +
			"what require_mfa and notify_on_use were. Missing it here means missing them.")
	}
}

// TestTheWireNameIsWhatTheCallerWrites. A finding names a field the operator has
// never heard of unless it also names the JSON key they set.
func TestTheWireNameIsWhatTheCallerWrites(t *testing.T) {
	switches, _, _, err := analyze([]string{"./testdata/switchfixture"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, s := range switches {
		if s.Key == "switchfixture.Request.Inert" && s.JSON != "inert" {
			t.Errorf("the finding would print %q; the caller writes \"inert\"", s.JSON)
		}
	}
}

// moduleOnce holds the expensive half: analyze over the whole module type-checks
// every package. deadconfig measured 8.8 GB peak and 75s wall for the same load
// under -race, and two such tests at once OOM-killed a 16 GB runner, so this is
// skipped under -short and under the race detector for the same reason its
// sibling is.
var (
	moduleOnce     sync.Once
	moduleSwitches []aSwitch
	moduleDecided  map[string]bool
	moduleErr      error
)

func moduleState(t *testing.T) ([]aSwitch, map[string]bool) {
	t.Helper()
	moduleOnce.Do(func() {
		switches, decided, excused, err := analyze([]string{"../../..."})
		if err != nil {
			moduleErr = err
			return
		}
		moduleSwitches = switches
		moduleDecided = map[string]bool{}
		for _, s := range switches {
			moduleDecided[s.Key] = decided[s.Decl] || excused[s.Decl]
		}
	})
	if moduleErr != nil {
		t.Fatalf("analyze: %v", moduleErr)
	}
	if len(moduleSwitches) == 0 {
		t.Fatal("no request switches found; the load found nothing and every check reading this " +
			"would pass vacuously")
	}
	return moduleSwitches, moduleDecided
}

// TestTheRegisterMatchesTheTree is the gate proper: every inert switch in the
// tree is registered with a verdict, and every registered switch is still inert.
func TestTheRegisterMatchesTheTree(t *testing.T) {
	if testing.Short() || racecost.Enabled {
		t.Skip("loads and type-checks the whole module; see moduleOnce")
	}
	switches, decided := moduleState(t)

	inert := map[string]bool{}
	for _, s := range switches {
		if !decided[s.Key] {
			inert[s.Key] = true
			if _, ok := knownInert[s.Key]; !ok {
				t.Errorf("%s (%s) is a switch a caller can set that nothing decides on, and it is "+
					"not in the register. Wire it, withdraw it, or record why it is not what it "+
					"looks like — at %s", s.Key, s.JSON, s.Pos)
			}
		}
	}
	for key := range knownInert {
		if !inert[key] {
			t.Errorf("%s is registered as inert and no longer reproduces. The register can only "+
				"shrink: delete its line in known.go.", key)
		}
	}
}

// TestTheSwitchThisGateWasBuiltForIsDecidedNow. notify_on_use is the reason this
// tool exists: bound, stored, selected back, rendered by the console, and never
// once compared. It must read as decided, and it must still be in the census —
// a field that vanished from the census would also "pass".
func TestTheSwitchThisGateWasBuiltForIsDecidedNow(t *testing.T) {
	if testing.Short() || racecost.Enabled {
		t.Skip("loads and type-checks the whole module; see moduleOnce")
	}
	switches, decided := moduleState(t)

	const key = "access.CreateTempAccessRequest.NotifyOnUse"
	found := false
	for _, s := range switches {
		if s.Key == key {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s is not in the census. Either the field is gone — in which case delete this "+
			"test — or the binder detection stopped seeing its handler, in which case this gate "+
			"is not watching the route it was built for.", key)
	}
	if !decided[key] {
		t.Errorf("%s reads as inert. It notifies the link's issuer at "+
			"internal/access/temp_access.go tempLinkNotifyRecipient; if that has been undone, "+
			"the console is offering a switch that does nothing again.", key)
	}
}
