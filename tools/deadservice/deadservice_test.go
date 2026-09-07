package main

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/ssa"
)

// The finding rule decides what this gate says about the tree, so it is tested
// directly against synthetic services and a synthetic reachable set: no build,
// no RTA, no fixtures on disk. TestTheRegisterMatchesTheTree below runs the
// real analysis and is the slow half.

// fn returns a distinct *ssa.Function to use as a map key. The analysis only
// ever compares identity, so an empty value is enough.
func fn() *ssa.Function { return &ssa.Function{} }

// svc builds a service whose methods are named m1..mN.
func svc(pkg, name string, n int) *service {
	s := &service{Pkg: pkg, Name: name, Funcs: map[string]*ssa.Function{}}
	for i := 1; i <= n; i++ {
		m := "m" + string(rune('0'+i))
		s.Methods = append(s.Methods, m)
		s.Funcs[m] = fn()
	}
	s.CtorName = "New" + name
	s.Ctor = fn()
	return s
}

func TestTheFindingRule(t *testing.T) {
	const pkg = "github.com/openidx/openidx/internal/example"

	t.Run("a service nothing constructs and nothing calls is a finding", func(t *testing.T) {
		s := svc(pkg, "Dead", 4)
		got := report([]*service{s}, map[*ssa.Function]bool{})
		if len(got) != 1 || got[0] != "internal/example.Dead" {
			t.Fatalf("got %v, want [internal/example.Dead]", got)
		}
	})

	t.Run("a reachable constructor clears the type", func(t *testing.T) {
		// The methods are all unreachable here, which happens constantly: a
		// live service with an unused accessor. Reporting it would bury the
		// findings that matter, and a gate that reports noise is a gate
		// somebody turns off.
		s := svc(pkg, "Live", 4)
		got := report([]*service{s}, map[*ssa.Function]bool{s.Ctor: true})
		if len(got) != 0 {
			t.Fatalf("got %v, want none: the constructor is reached", got)
		}
	})

	t.Run("one reachable method clears the type", func(t *testing.T) {
		// A type built by a composite literal rather than its constructor --
		// internal/identity.Group and internal/identity.User are both like this
		// in the real tree, with an unreachable NewGroup/NewUser and every
		// method live. Calling those dead would be a false report.
		s := svc(pkg, "Partly", 4)
		got := report([]*service{s}, map[*ssa.Function]bool{s.Funcs["m3"]: true})
		if len(got) != 0 {
			t.Fatalf("got %v, want none: one method is reached", got)
		}
	})

	t.Run("a type with no constructor is judged on its methods alone", func(t *testing.T) {
		s := svc(pkg, "NoCtor", 3)
		s.CtorName, s.Ctor = "", nil
		if got := report([]*service{s}, map[*ssa.Function]bool{}); len(got) != 1 {
			t.Fatalf("got %v, want one finding", got)
		}
		if got := report([]*service{s}, map[*ssa.Function]bool{s.Funcs["m1"]: true}); len(got) != 0 {
			t.Fatalf("got %v, want none", got)
		}
	})

	t.Run("findings come back sorted", func(t *testing.T) {
		a, b, c := svc(pkg, "Zulu", 3), svc(pkg, "Alpha", 3), svc(pkg, "Mike", 3)
		got := report([]*service{a, b, c}, map[*ssa.Function]bool{})
		want := []string{"internal/example.Alpha", "internal/example.Mike", "internal/example.Zulu"}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})
}

func TestTheRegisterKeyIsThePackageTail(t *testing.T) {
	for _, tc := range []struct{ pkg, name, want string }{
		{"github.com/openidx/openidx/internal/governance", "RequestService", "internal/governance.RequestService"},
		{"github.com/openidx/openidx/internal/gateway/middleware", "JWTAuthMiddleware", "internal/gateway/middleware.JWTAuthMiddleware"},
		{"github.com/openidx/openidx/internal/common/cache", "Cache", "internal/common/cache.Cache"},
	} {
		s := &service{Pkg: tc.pkg, Name: tc.name}
		if got := s.key(); got != tc.want {
			t.Errorf("key(%s, %s) = %q, want %q", tc.pkg, tc.name, got, tc.want)
		}
	}
}

func TestEveryRegisterEntryCarriesAVerdict(t *testing.T) {
	// A register of bare names is a suppression list. The verdict is what makes
	// it a backlog: what the service looks like it does, what actually happens,
	// and whether the answer is to wire it or delete it.
	for key, verdict := range knownDead {
		if len(strings.TrimSpace(verdict)) < 80 {
			t.Errorf("%s: verdict is too short to say what the service is and what should happen to it: %q", key, verdict)
		}
		if !strings.Contains(key, ".") {
			t.Errorf("%s: register keys are <package tail>.<TypeName>", key)
		}
	}
}

// TestTheRegisterMatchesTheTree runs the real analysis. It is the slow test in
// this package (RTA over every binary, ~20s) and it is the one that matters: a
// register that has drifted from the tree is a checker that has quietly stopped
// checking.
func TestTheRegisterMatchesTheTree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the whole-program analysis under -short")
	}
	services, reachable, err := analyze("../../cmd/...")
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	findings := report(services, reachable)

	found := map[string]bool{}
	for _, f := range findings {
		found[f] = true
		if _, ok := knownDead[f]; !ok {
			t.Errorf("%s is unreachable and unregistered: read what it looks like it does, then wire it, delete it, or record the verdict in known.go", f)
		}
	}
	for k := range knownDead {
		if !found[k] {
			t.Errorf("%s is registered as unreachable but a binary reaches it now: remove its entry, the register only shrinks", k)
		}
	}
}
