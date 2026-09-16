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

// What a path takes away. Both leave a live credential in an issued token, and
// the remedy is the same marker, but the sentence an engineer needs to read is
// not: one is "this account is gone", the other "this role is gone".
const (
	seversAccount = "account"
	seversGrant   = "grant"
	seversCascade = "cascade"
)

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

	// ---- the grant shape -------------------------------------------------

	"internal/identity/group_repository.go::Delete": {revokedByCaller,
		"Service.DeleteGroup calls this and cuts the tokens of everyone it returns. The repository has no " +
			"Redis and should not: deleting a group is a mass removal, so the fix was to make this say WHICH " +
			"users it removed (RETURNING user_id) rather than to give the row-removal layer a marker write. " +
			"Verified by reading that caller."},

	"internal/jitgrant/jitgrant.go::Revoke": {revokedByCaller,
		"this is the shared primitive, and the revoke deliberately lives in its callers: it takes an Execer " +
			"so a caller can run it inside its own transaction, Redis cannot join a Postgres transaction, " +
			"and a marker written inside a transaction that later rolls back logs a user out of access they " +
			"still hold. Every caller was read: governance's review decision (both the single and batch " +
			"paths, after tx.Commit), its JIT expiry sweep, EndAllForUser's two callers (deprovisionUser and " +
			"the kill switch) and EndAllForDisabledUsers via the lifecycle sweep."},

	"internal/directory/sync.go::deleteSyncedGroup": {revokesIndirectly,
		"the cascade path, fixed: group_memberships.group_id is ON DELETE CASCADE, so deleting a group the " +
			"directory no longer has removes every membership without the statement naming the child table. " +
			"It reads the members BEFORE the delete -- a cascade returns nothing, so RETURNING is not " +
			"available here -- and cuts them after. Listed for the same reason as the entries below: the cut " +
			"goes through the injected e.revoke, which name-based reachability cannot follow."},

	"internal/directory/sync.go::replaceDirectoryMemberships": {revokesIndirectly,
		"FIXED, and listed only because the census cannot see the fix. It now DELETEs ... RETURNING user_id, " +
			"subtracts the members it re-inserts, and cuts the difference after the commit -- because a " +
			"replacement is a grant and a revocation at once, and cutting on the delete would log out every " +
			"member of every synced group on every sync. The cut goes through e.revokeTokens -> e.revoke, a " +
			"function-valued field with no declared name for this census to follow, the same indirection as " +
			"deprovisionHR below. revoker_wiring_test.go fails when a binary that starts the scheduler does " +
			"not supply the callback."},

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
	severs, satisfied, grantShape := severCensus(t)

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
		if grantShape[key] {
			t.Errorf("%s takes a role or a group away and no path from it writes the revocation marker.\n"+
				"Removing the assignment stops the NEXT login. The enforcement point reads the role list from "+
				"the token's \"roles\" claim and resolves that set's permissions itself, and \"groups\" is a "+
				"claim for the same reason -- so a token issued before the DELETE still names what was taken "+
				"away, and keeps working until it expires. Call revocation.RevokeUserTokens AFTER the removal "+
				"commits (Redis cannot join a Postgres transaction), or record the verdict in severRegister "+
				"with the reason.", key)
			continue
		}
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
func severCensus(t *testing.T) (severs []string, satisfied, grantShape map[string]bool) {
	t.Helper()
	type fn struct {
		key     string
		severs  bool
		shape   string
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
						f.shape = seversAccount
					}
					// The SECOND shape. Taking a role or a group away does not
					// touch the user row, so the check above never saw it --
					// and the token carries both: the enforcement point reads
					// the role list from the "roles" claim and resolves that
					// set's permissions itself, and "groups" is a claim for the
					// same reason. A token issued before the DELETE still names
					// what was taken away.
					//
					// user_application_assignments is deliberately NOT here:
					// it appears in no claim, so the row being gone IS the
					// enforcement (jitgrant.TokenCarries is where that decision
					// is written down).
					if strings.Contains(v, "delete from user_roles") ||
						strings.Contains(v, "delete from group_memberships") {
						f.severs = true
						if f.shape == "" {
							f.shape = seversGrant
						}
					}
					// THE THIRD SHAPE, AND THE ONE THAT HID FROM THE SECOND.
					// group_memberships.group_id and user_roles.role_id both
					// carry ON DELETE CASCADE, so deleting the PARENT takes
					// every assignment with it -- and the statement never names
					// the child table, so the check above cannot see it. Three
					// live paths were in exactly that position: SCIM group
					// deletion and the LDAP and Azure AD syncs dropping a group
					// the directory no longer has. Each one silently removed a
					// claim from every member while their tokens kept asserting
					// it, and a census that only reads the SQL it is shown
					// would have reported the set closed.
					//
					// A cascade returns nothing, so these paths cannot use
					// RETURNING: they have to read the members before the
					// delete. That is a different fix, which is why it is a
					// different shape rather than one more string here.
					if strings.Contains(v, "delete from groups ") ||
						strings.Contains(v, "delete from roles ") {
						f.severs = true
						if f.shape == "" {
							f.shape = seversCascade
						}
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
	grantShape = map[string]bool{}
	for _, f := range ordered {
		if !f.severs {
			continue
		}
		severs = append(severs, f.key)
		if f.shape == seversGrant || f.shape == seversCascade {
			grantShape[f.key] = true
		}
		if f.revokes {
			satisfied[f.key] = true
		}
	}
	sort.Strings(severs)
	return severs, satisfied, grantShape
}
