package revocation_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// EVERY PATH THAT SEVERS A USER'S ACCESS HAS TO WRITE THE MARKER, and this
// counts the ones that do not.
//
// The package doc records half of this defect: governance wrote the marker to a
// key nothing read, so an access review revoked somebody and their session kept
// working. The other half is a path that severs and writes NO marker at all,
// and the doc names deprovisionUser and the kill switch as having been exactly
// that. Those two were fixed. NOBODY COUNTED THE REST.
//
// The rest is: disabling an account on a federated partner's CAEP signal,
// auto-locking one on a detected anomaly, offboarding a leaver, a lifecycle
// policy, a bulk disable, a quarantine, a DSAR, an HR feed saying the person
// has gone. Each stops the next login. None of them is read by
// /oauth/userinfo or /oauth/introspect, which consult the per-user marker and
// the per-token blacklist and nothing else -- so the access token already in
// that browser keeps answering until it expires on its own.
//
// This census finds the severing functions itself rather than trusting a list,
// the same shape as the sweeps census and tools/deadservice. A function severs
// if it disables or deletes a user row; it is satisfied if it, or anything it
// calls, writes the marker. Everything left over must be in the register below
// WITH A REASON, and an entry that stops reproducing fails the run -- so the
// list can only shrink.

// sever verdicts.
const (
	// revokedByCaller: the sever is a primitive and its CALLER writes the
	// marker before calling it. Verified by reading the caller, not assumed.
	revokedByCaller = "revoked-by-caller"
	// revokesIndirectly: it does revoke, through something this census cannot
	// follow -- a function-valued field, which name-based reachability has no
	// way to resolve. Recorded rather than papered over, because the honest
	// statement is "the guard cannot see this one", not "this one is fine".
	revokesIndirectly = "revokes-indirectly"
	// unaudited: counted and named, never silent. Same role as the sweeps
	// census's "undecided" and orgscope's needsScoping register.
	unaudited = "unaudited"
)

var severRegister = map[string]struct{ verdict, reason string }{
	"internal/identity/user_repository.go::Delete": {revokedByCaller,
		"Service.DeleteUser calls deprovisionUser -- which writes the marker -- BEFORE this, deliberately, " +
			"so a concurrent refresh grant cannot slip through against a still-present user. Verified by " +
			"reading that caller; this function is the row removal and nothing else, as its own comment says."},

	"internal/admin/ibdr.go::executeFullQuarantine": {revokesIndirectly,
		"it calls the revoke function the admin Service injects, which reaches RevokeUserTokens. A field " +
			"call has no declared name, so this census's name-based reachability cannot follow it. The " +
			"indirection is deliberate: ibdrService is built from the admin Service, and giving it its own " +
			"Redis client is how this product ended up with several hand-rolled copies of one marker write."},

	// ---- internal/directory ------------------------------------------------
	//
	// THE FIRST VERSION OF THIS REGISTER CALLED THESE "no revocation client",
	// AND THAT WAS WRONG. It was read off the SyncEngine struct -- a database
	// handle and a logger, nothing else -- and turned into a claim about the
	// package, and from there into a claim that only the event bus could fix
	// them. Checking the call sites instead of the struct took two minutes and
	// showed the opposite: Service already takes a *redis.Client through
	// SetRedis, and both binaries that START the scheduler already pass one.
	//
	// The plumbing was a small change, so it was made rather than deferred to
	// an architecture that does not exist yet. What makes it worth recording
	// is the shape of the mistake: a struct with two fields is evidence about
	// that struct, not about what its callers can reach, and "this needs the
	// bus" is the most expensive possible conclusion to draw from two minutes
	// of not looking.
	//
	// They stay listed because the census cannot SEE the fix: `e.revoke(...)`
	// is a call through a struct field and name-based reachability has no
	// declared name to follow, exactly as for the quarantine above. Two guards
	// cover what it cannot: directory's revoker_wiring_test.go fails when a
	// binary that starts the scheduler does not supply the callback, and
	// deprovision_revokes_testdb_test.go drives a real deprovision against a
	// real PostgreSQL and fails if the engine does not call it.
	"internal/directory/hris_sync.go::deprovisionHR": {revokesIndirectly,
		"calls e.revokeTokens, which calls the injected callback; guarded by revoker_wiring_test.go and " +
			"measured end to end by deprovision_revokes_testdb_test.go, both in internal/directory"},
	"internal/directory/sync.go::syncAzureADUsers": {revokesIndirectly,
		"calls e.revokeTokens on both the disable and the delete branch; same two guards as deprovisionHR"},
	"internal/directory/sync.go::syncUsers": {revokesIndirectly,
		"calls e.revokeTokens on both the disable and the delete branch; same two guards as deprovisionHR"},
}

func TestEverySeverPathRevokesOrIsOnTheRegister(t *testing.T) {
	severs, satisfied := severCensus(t)

	// Vacuity: a census that finds nothing proves nothing, and would also mean
	// no path in this product disables or deletes a user.
	if len(severs) < 10 {
		t.Fatalf("only %d severing functions found; this census is looking at the wrong tree or no longer "+
			"recognises how an account is disabled", len(severs))
	}

	var unregistered []string
	for _, key := range severs {
		if satisfied[key] {
			continue
		}
		if _, ok := severRegister[key]; !ok {
			unregistered = append(unregistered, key)
		}
	}
	sort.Strings(unregistered)
	for _, key := range unregistered {
		t.Errorf("%s severs a user's access and no path from it writes the revocation marker.\n"+
			"Disabling or deleting the row stops the NEXT login. /oauth/userinfo and /oauth/introspect read "+
			"the per-user marker and the per-token blacklist and nothing else, so the access token already in "+
			"that browser keeps answering until it expires. Call revocation.RevokeUserTokens after the sever, "+
			"or record the verdict in severRegister with the reason.", key)
	}

	// A register entry that no longer reproduces is as much a defect as an
	// unregistered finding: it means either the path was fixed and the line
	// should go, or the census stopped seeing it. The list only shrinks.
	for key, entry := range severRegister {
		found := false
		for _, k := range severs {
			if k == key {
				found = true
			}
		}
		if !found {
			t.Errorf("severRegister names %s, which this census no longer finds as a severing path. "+
				"If it was fixed, delete the line (%s: %s). If it moved, the census stopped seeing it.",
				key, entry.verdict, entry.reason)
			continue
		}
		if satisfied[key] && entry.verdict != revokedByCaller && entry.verdict != revokesIndirectly {
			t.Errorf("severRegister names %s as %q, but it revokes now. Delete the line.", key, entry.verdict)
		}
	}
}

// The register is a backlog, not a suppression list: every entry carries one of
// the known verdicts and a reason somebody can act on.
func TestEverySeverRegisterEntryHasAVerdictAndAReason(t *testing.T) {
	for key, entry := range severRegister {
		switch entry.verdict {
		case revokedByCaller, revokesIndirectly, unaudited:
		default:
			t.Errorf("%s: %q is not a verdict this census knows", key, entry.verdict)
		}
		if len(strings.TrimSpace(entry.reason)) < 30 {
			t.Errorf("%s: the reason is too short to act on: %q", key, entry.reason)
		}
	}
}

// severCensus returns every function that disables or deletes a user, and which
// of them reach revocation.RevokeUserTokens directly or through a call.
func severCensus(t *testing.T) (severs []string, satisfied map[string]bool) {
	t.Helper()
	type fn struct {
		key     string
		severs  bool
		revokes bool
		calls   map[string]bool
	}
	fset := token.NewFileSet()
	byName := map[string][]*fn{}
	var ordered []*fn

	root := ".."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))
		// Migration descriptions quote this SQL in prose; they change no rows.
		if strings.HasPrefix(rel, "migrations/") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		parsed, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			return nil
		}
		for _, decl := range parsed.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			f := &fn{key: fmt.Sprintf("internal/%s::%s", rel, fd.Name.Name), calls: map[string]bool{}}
			ast.Inspect(fd, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v := strings.ToLower(lit.Value)
					if (strings.Contains(v, "update users") && strings.Contains(v, "enabled") && strings.Contains(v, "false")) ||
						strings.Contains(v, "delete from users") {
						f.severs = true
					}
				}
				switch e := n.(type) {
				case *ast.SelectorExpr:
					if e.Sel.Name == "RevokeUserTokens" {
						f.revokes = true
					}
					f.calls[e.Sel.Name] = true
				case *ast.Ident:
					f.calls[e.Name] = true
				}
				return true
			})
			byName[fd.Name.Name] = append(byName[fd.Name.Name], f)
			ordered = append(ordered, f)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Reachability by name. It cannot resolve a receiver type, so it is
	// generous: a function is credited when SOMETHING with that name revokes.
	// Generous in the safe direction -- it under-reports rather than accusing
	// a path that is fine -- and the register carries what it gets wrong.
	for changed := true; changed; {
		changed = false
		for _, f := range ordered {
			if f.revokes {
				continue
			}
			for c := range f.calls {
				for _, g := range byName[c] {
					if g.revokes {
						f.revokes, changed = true, true
					}
				}
			}
		}
	}

	satisfied = map[string]bool{}
	for _, f := range ordered {
		if !f.severs {
			continue
		}
		severs = append(severs, f.key)
		if f.revokes {
			satisfied[f.key] = true
		}
	}
	sort.Strings(severs)
	return severs, satisfied
}
