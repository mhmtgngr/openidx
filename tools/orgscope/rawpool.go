package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// The Raw() rule (global-scale plan task 2.1b).
//
// WHAT Raw() IS. Task 2.1b moved the tenant scope into the type of
// PostgresDB.Pool: db.Pool.Query / QueryRow / Exec run inside a scoped
// transaction when RLS_MODE=local. ScopedPool.Raw() is the deliberate way out,
// for the cases that genuinely have no tenant: install-wide tables
// (oauth_signing_keys, system_settings, migrations), pool statistics, and
// anything running before a tenant exists.
//
// WHY IT NEEDS A LINT. Raw() is exactly as easy to type as Pool, and the
// difference between them is invisible at the call site and at compile time.
// Reach a tenant table through it in local mode and the query carries no
// app.org_id at all -- under FORCE RLS that is not an error, it is ZERO ROWS.
// A user lookup returns "no such user"; a list returns empty; nothing logs and
// nothing fails. That is a worse failure than a crash, and it is one character
// of difference away at every one of ~1,950 call sites.
//
// This file asks two questions the type system cannot:
//
//	(a) does a SQL literal that names a scoped table travel through Raw()?
//	(b) is a Raw() pool handed to something that this tool has not vetted?
//
// (b) matters because the hazard travels: signingkeys.NewStore(db.Pool.Raw())
// is correct only because oauth_signing_keys is install-wide, and nothing at
// that call site says so. The allowlist below is where that judgement lives,
// with its reason, once -- the same pattern as installWideTables.

// rawHandoffAllowed names the functions that may receive an unscoped pool,
// each with the reason it is safe. Anything else is a blocking finding.
//
// A reason is mandatory (init below rejects a blank one), so a handoff can
// never be waved through unexplained. Keys are written as they appear in the
// source: "pkg.Func" for a qualified call, "Func" for a package-local one.
var rawHandoffAllowed = map[string]string{
	"metrics.NewTracedPool": "pool statistics only; it reads pgxpool.Stat and runs no query",

	"migrations.NewMigrator":     "DDL as the schema owner, before any request and with no tenant",
	"migrations.MustAutoMigrate": "same as NewMigrator: startup DDL, no tenant context exists yet",

	"signingkeys.NewStore": "oauth_signing_keys is install-wide (declared in installWideTables): one key set serves every tenant, so there is no scope to carry",

	"withTxOn": "the scoped-transaction helper itself; it takes the raw pool precisely so it can BEGIN and stamp the scope with set_config(..., true)",
}

// rawFindingKind marks the two findings this file produces, so Finding.String
// can say what actually went wrong instead of "used without org_id" -- which
// would be misleading here: adding org_id to the SQL does NOT fix a Raw()
// query. The policy is USING (org_id = current_setting('app.org_id')), so with
// no GUC set the row is invisible whatever the WHERE clause says.
const (
	rawKindQuery   = "raw-query"
	rawKindHandoff = "raw-handoff"
	rawKindOpaque  = "raw-opaque"
)

// queryMethods are the ScopedPool/pgxpool methods that reach the database. A
// call to one of these off a Raw() pool is unscoped by construction.
var queryMethods = map[string]bool{
	"Query": true, "QueryRow": true, "Exec": true,
	"Begin": true, "BeginTx": true, "SendBatch": true, "CopyFrom": true,
}

// callName renders a call's callee as it is written in the source:
// "pkg.Func", "recv.Method" or "Func". Returns "" for anything more
// complicated (a call through a func value, say), which the caller treats as
// not-on-the-allowlist.
func callName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
		return f.Sel.Name
	}
	return ""
}

// isRawCall reports whether e is a call to something named Raw with no
// arguments -- db.Pool.Raw(), p.Raw(), db.Reader().Raw().
func isRawCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Raw"
}

// unparen strips redundant parentheses: ((db.Pool.Raw())) is db.Pool.Raw().
func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// reachesRaw reports whether e's receiver chain passes through a Raw() call.
// db.Pool.Raw().QueryRow(...) is SelectorExpr{X: CallExpr(Raw), Sel: QueryRow},
// so the walk is down the X spine.
func reachesRaw(e ast.Expr) bool {
	for {
		if isRawCall(e) {
			return true
		}
		switch n := e.(type) {
		case *ast.SelectorExpr:
			e = n.X
		case *ast.CallExpr:
			e = n.Fun
		case *ast.IndexExpr:
			e = n.X
		case *ast.ParenExpr:
			e = n.X
		default:
			return false
		}
	}
}

// rawQueryFindings reports scoped tables reached through Raw().
//
// Unlike analyzeSQL this does NOT let an org_id in the SQL clear the finding.
// That is the whole point: the RLS policy compares org_id to
// current_setting('app.org_id'), so a query with no scope set sees nothing
// however carefully its WHERE clause is written.
func rawQueryFindings(sql string) []Finding {
	seen := map[string]bool{}
	var findings []Finding
	for _, t := range extractTables(sql) {
		if seen[t] || !scopedTables[t] {
			continue
		}
		seen[t] = true
		findings = append(findings, Finding{
			Kind:  rawKindQuery,
			Table: t,
			SQL:   sql,
			Reason: "reached through Raw(), which carries no tenant scope; " +
				"in RLS_MODE=local FORCE RLS answers this with zero rows, and an org_id in the SQL does not help",
		})
	}
	return findings
}

// rawHandoffFinding reports an unscoped pool passed to a function that is not
// on rawHandoffAllowed.
//
// The argument must BE the pool -- exactly `something.Raw()` -- not merely
// something derived from it. That distinction matters: the read-path
// repositories are written as scanUser(r.db.Reader().QueryRow(...)), so a rule
// that matched "anything whose chain touches Raw()" would report scanUser as
// receiving a pool it never sees, and bury the real finding (the QueryRow
// itself, which rawQueryCallFindings reports) under a wrong one.
func rawHandoffFinding(call *ast.CallExpr, fset *token.FileSet) []Finding {
	name := callName(call.Fun)
	if _, ok := rawHandoffAllowed[name]; ok {
		return nil
	}
	var findings []Finding
	for _, arg := range call.Args {
		if !isRawCall(unparen(arg)) {
			continue
		}
		shown := name
		if shown == "" {
			shown = "an unnamed callee"
		}
		findings = append(findings, Finding{
			Kind: rawKindHandoff,
			Pos:  fset.Position(call.Pos()),
			Reason: fmt.Sprintf("unscoped pool handed to %s, which is not on rawHandoffAllowed; "+
				"whatever it queries runs with no tenant scope in RLS_MODE=local. "+
				"Pass db.Pool instead, or add %s to rawHandoffAllowed with the reason it needs the raw pool",
				shown, shown),
			SQL: shown,
		})
	}
	return findings
}

// rawQueryCallFindings reports a database call made through Raw().
//
// When the SQL is a literal we can read, the answer is per-table: an
// install-wide table is the correct use of Raw() and stays silent. When it is
// not -- a `query` variable, a builder, a constant from elsewhere, which is how
// much of this repo is written -- the tool cannot tell which tables it touches,
// so it FAILS CLOSED and asks for a reason. That is the right default for the
// one call that deliberately leaves the tenant belt behind.
func rawQueryCallFindings(call *ast.CallExpr, fset *token.FileSet) []Finding {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !queryMethods[sel.Sel.Name] || !reachesRaw(sel.X) {
		return nil
	}
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		sql, ok := literalString(lit)
		if !ok || !startsWithSQLKeyword(sql) {
			continue
		}
		out := rawQueryFindings(sql)
		for i := range out {
			out[i].Pos = fset.Position(lit.Pos())
		}
		return out
	}
	// No readable SQL. Begin()/BeginTx() legitimately have none -- but a
	// transaction opened on the raw pool is unscoped for every statement in
	// it, which is the same hazard, so they are reported too.
	return []Finding{{
		Kind: rawKindOpaque,
		Pos:  fset.Position(call.Pos()),
		Reason: fmt.Sprintf("%s through Raw() with SQL this tool cannot read, so it cannot tell whether the tables are tenant ones; "+
			"in RLS_MODE=local it carries no scope. Use db.Pool, or add //orgscope:ignore <reason> saying which install-wide tables it touches",
			sel.Sel.Name),
		SQL: sel.Sel.Name,
	}}
}

func init() {
	for fn, reason := range rawHandoffAllowed {
		if strings.TrimSpace(reason) == "" {
			panic("orgscope: rawHandoffAllowed[" + fn + "] has no reason; every entry must say why")
		}
	}
}
