package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A transmitter advertises what it can send. /.well-known/ssf-configuration
// lists events_supported, a receiver reads that list, subscribes to what it
// needs, and waits. If the product never emits one of those events the receiver
// is not misconfigured and has nothing to debug: it asked for what it was
// offered, and the offer was not true.
//
// That is this branch's recurring shape one layer up. Everywhere else it was a
// control reporting success while the thing it was meant to make true was not
// true; here it is a capability document describing a product that does not
// exist. The cost lands on somebody wiring their downstream apps to CAEP so a
// disabled account drops out of them immediately -- exactly the person the
// feature is for.
//
// So the advertisement is derived from the emitters rather than written beside
// them. Adding an event to events_supported without an EmitCAEPEvent call for
// it fails here, and so does deleting the last emitter of an advertised event.

// eventConstants are the CAEP/RISC event-type constants this package defines.
// Read from the source rather than listed, so a new one cannot be added to
// ssf.go and quietly skipped here.
func eventConstants(t *testing.T) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "ssf.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ssf.go: %v", err)
	}
	found := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if !strings.HasPrefix(name.Name, "Event") || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || !strings.Contains(lit.Value, "secevent") {
				continue
			}
			found[name.Name] = true
		}
		return true
	})
	if len(found) < 3 {
		t.Fatalf("found %d event-type constants in ssf.go; the census is reading nothing", len(found))
	}
	return found
}

// identsIn returns every identifier used anywhere in the package's production
// files inside a call to fn, at the given argument position.
func identsInCallArg(t *testing.T, fn string, arg int) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files++
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var called string
			switch c := call.Fun.(type) {
			case *ast.SelectorExpr:
				called = c.Sel.Name
			case *ast.Ident:
				called = c.Name
			}
			if called != fn || arg >= len(call.Args) {
				return true
			}
			if id, ok := call.Args[arg].(*ast.Ident); ok {
				out[id.Name] = true
			}
			return true
		})
	}
	if files < 10 {
		t.Fatalf("walked only %d production files; the census is reading nothing", files)
	}
	return out
}

// advertisedEvents are the constants in ssfEventsSupported, read from the
// source -- and the census also holds handleSSFConfiguration's
// events_supported key to THAT variable. The variable is what events_delivered
// is computed from, so if the handler grew its own literal list again the
// discovery document and the stream configuration could offer two different
// sets, and this census would be reading the one the receiver never sees.
func advertisedEvents(t *testing.T) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "ssf_handlers.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ssf_handlers.go: %v", err)
	}
	out := map[string]bool{}
	handlerRefersToVar := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			for i, name := range v.Names {
				if name.Name != "ssfEventsSupported" || i >= len(v.Values) {
					continue
				}
				ast.Inspect(v.Values[i], func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok && strings.HasPrefix(id.Name, "Event") {
						out[id.Name] = true
					}
					return true
				})
			}
		case *ast.KeyValueExpr:
			key, ok := v.Key.(*ast.BasicLit)
			if !ok || !strings.Contains(key.Value, "events_supported") {
				return true
			}
			if id, ok := v.Value.(*ast.Ident); ok && id.Name == "ssfEventsSupported" {
				handlerRefersToVar = true
			} else {
				t.Errorf("handleSSFConfiguration's events_supported is not the variable ssfEventsSupported; " +
					"the discovery document and events_delivered would be computed from two lists")
			}
			return false
		}
		return true
	})
	if len(out) == 0 {
		t.Fatal("found no ssfEventsSupported entries; the census is reading nothing")
	}
	if !handlerRefersToVar {
		t.Error("handleSSFConfiguration does not advertise ssfEventsSupported under events_supported")
	}
	return out
}

func TestEverySSFEventAdvertisedIsActuallyEmitted(t *testing.T) {
	known := eventConstants(t)
	advertised := advertisedEvents(t)
	// EmitCAEPEvent(ctx, orgID, eventType, ...) -- the event type is arg 2.
	emitted := identsInCallArg(t, "EmitCAEPEvent", 2)

	var silent []string
	for name := range advertised {
		if !emitted[name] {
			silent = append(silent, name)
		}
	}
	sort.Strings(silent)
	if len(silent) > 0 {
		t.Errorf("/.well-known/ssf-configuration advertises %d event type(s) that nothing emits:\n  %s\n\n"+
			"A receiver reads that list, subscribes, and waits forever. Either emit the event from the "+
			"path that causes it, or stop advertising it -- an events_supported entry is a promise to "+
			"somebody wiring their downstream apps to CAEP.\n"+
			"Emitters live wherever EmitCAEPEvent is called; note that it is an internal/oauth method, so "+
			"a cause outside this service reaches it through the outbox rather than directly.",
			len(silent), strings.Join(silent, "\n  "))
	}

	// And the other direction: an emitter for something never offered is a SET
	// no receiver can have subscribed to.
	for name := range emitted {
		if known[name] && !advertised[name] {
			t.Errorf("%s is emitted but not in events_supported: no receiver can subscribe to it", name)
		}
	}
}
