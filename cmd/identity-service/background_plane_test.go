package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// The plane split has to reach the background work, not just the routes.
//
// SERVICE_PROFILE=auth exists so the ISSUE half serves login and nothing else.
// It registered the right routes from the start and then started every sweep
// anyway, because the starters sat below the profile check and never consulted
// it. The plan recorded that as deferred to the worker item; this is the part
// of it identity-service can settle on its own.
//
// It matters for a reason that is LATENT RATHER THAN LIVE, and the distinction
// is the point. The role-expiry sweep is leader-gated, so the cost was already
// one replica per minute cluster-wide, and today an auth pod winning that
// election is harmless: values.yaml assigns BOTH halves the `admin` database
// role. The move that file names as next -- the auth half to `issue`, whose
// statement_timeout is sized for a login query -- is what turns it into a sweep
// that fails every tick it wins. Gating it now means that move stays a
// configuration change instead of becoming an incident.
//
// So each background starter is classified, and main.go has to agree with the
// classification. The register only shrinks: a new starter with no entry fails.

// adminPlaneStarters do work that belongs to the ADMIN plane and must sit
// behind the profile check.
var adminPlaneStarters = map[string]string{
	"StartRoleExpirationChecker": "deletes expired time-bound role assignments across every org and revokes the tokens carrying them; nothing about it belongs to a login",
}

// everyProfileStarters run in every profile, with the reason. These are not
// leftovers: each one maintains state belonging to THIS process, so a pod that
// skipped it would be the pod that is wrong.
var everyProfileStarters = map[string]string{
	"StartSMSConfigWatcher":   "swaps this process's own SMS provider from a settings row and writes nothing. The auth half sends the MFA codes, so it is the last pod that should miss the swap; internal/common/leader's sweeps census records it as per-process for the same reason",
	"StartPoolStatsCollector": "reports this process's own pool gauges; gating it would leave every non-admin pod reporting nothing",
}

// isBackgroundStarter matches Start<Something>, the shape every background
// starter in this tree uses. A bare Start() is the graceful-shutdown server
// handing over the process, not background work, so it is not one of these.
func isBackgroundStarter(name string) bool {
	if !strings.HasPrefix(name, "Start") || len(name) == len("Start") {
		return false
	}
	c := name[len("Start")]
	return c >= 'A' && c <= 'Z'
}

// starterCalls returns each Start* call in main.go with whether it is
// (transitively) inside an `if` that tests the service profile.
func starterCalls(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	gated := map[string]bool{}
	var stack []ast.Node

	profileGuarded := func() bool {
		for _, n := range stack {
			ifs, ok := n.(*ast.IfStmt)
			if !ok {
				continue
			}
			var buf strings.Builder
			ast.Inspect(ifs.Cond, func(c ast.Node) bool {
				switch v := c.(type) {
				case *ast.Ident:
					buf.WriteString(v.Name + " ")
				case *ast.SelectorExpr:
					buf.WriteString(v.Sel.Name + " ")
				}
				return true
			})
			cond := buf.String()
			if strings.Contains(cond, "serviceProfile") || strings.Contains(cond, "ServesAdmin") ||
				strings.Contains(cond, "ServesIssue") || strings.Contains(cond, "Profile") {
				return true
			}
		}
		return false
	}

	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !isBackgroundStarter(sel.Sel.Name) {
			return true
		}
		name := sel.Sel.Name
		// A starter called in several places is gated only if every call is.
		if prev, seen := gated[name]; seen {
			gated[name] = prev && profileGuarded()
		} else {
			gated[name] = profileGuarded()
		}
		return true
	})

	if len(gated) < 2 {
		t.Fatalf("found %d Start* calls in main.go; the census is reading nothing", len(gated))
	}
	return gated
}

func TestBackgroundWorkRespectsTheServiceProfile(t *testing.T) {
	gated := starterCalls(t)

	var unclassified []string
	for name := range gated {
		_, admin := adminPlaneStarters[name]
		_, every := everyProfileStarters[name]
		switch {
		case admin && every:
			t.Errorf("%s is in both registers; it belongs to one plane or to all of them", name)
		case admin:
			if !gated[name] {
				t.Errorf("%s does ADMIN-plane work but starts unconditionally:\n  %s\n\n"+
					"With SERVICE_PROFILE=auth the ISSUE half would run it, which is what the plane "+
					"split exists to prevent. Put it behind serviceProfile.ServesAdmin().",
					name, adminPlaneStarters[name])
			}
		case every:
			if gated[name] {
				t.Errorf("%s is registered as running in every profile, but main.go gates it:\n  %s\n\n"+
					"Either the reason is now wrong and it belongs in adminPlaneStarters, or the gate "+
					"is the defect -- a pod skipping it is the pod that is wrong.",
					name, everyProfileStarters[name])
			}
		default:
			unclassified = append(unclassified, name)
		}
	}

	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("background starter(s) in main.go with no plane recorded:\n  %s\n\n"+
			"Say which plane the work belongs to. ADMIN-plane work goes behind "+
			"serviceProfile.ServesAdmin() and into adminPlaneStarters; work that maintains this "+
			"process's own state goes in everyProfileStarters with the reason a pod skipping it "+
			"would be wrong.", strings.Join(unclassified, "\n  "))
	}

	// Registers may not outlive the code they describe.
	for name := range adminPlaneStarters {
		if _, ok := gated[name]; !ok {
			t.Errorf("adminPlaneStarters names %s, which main.go no longer calls; remove the entry", name)
		}
	}
	for name := range everyProfileStarters {
		if _, ok := gated[name]; !ok {
			t.Errorf("everyProfileStarters names %s, which main.go no longer calls; remove the entry", name)
		}
	}
}
