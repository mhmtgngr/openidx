package main

// The tenant-scope census, derived from the migration registry.
//
// WHY THIS EXISTS. Until now scoped.go was a hand-maintained list of ~90 table
// names, and sqlcheck.go only asked its question about tables on that list. A
// table nobody remembered to add was not "unchecked" in a way anyone could
// see -- it was invisible. That is not a hypothetical: ispm_rules,
// ispm_findings, ispm_scores, ai_agents (+3 children) and ai_recommendations
// (+1 child) were created without org_id in v42/v43/v54, never appeared here,
// and internal/admin read, updated and DELETEd them across tenants for nine
// releases while this lint reported zero findings on every one of those PRs.
//
// So the list is now derived, not written. The migration registry is the only
// place that knows every table the schema has, and folding its DDL in version
// order answers three questions per table: does it carry org_id, does it have
// FORCE ROW LEVEL SECURITY, and does it still exist. From those, omission
// becomes a finding rather than a blind spot:
//
//   - a table with org_id whose queries drop the predicate  -> the original rule
//   - a table with NO org_id that is not declared install-wide, with a reason
//   - a table with org_id but no RLS belt, not declared exempt, with a reason
//
// Heuristic, like the rest of this tool: it reads DDL text, not a Postgres
// parser. The self-tests in ddl_test.go pin each rule, and
// TestDerivedSetCoversFormerHandList pins the derivation against the list it
// replaced so coverage cannot silently shrink.

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openidx/openidx/internal/migrations"
)

// tableFacts is what the accumulated DDL says about one table.
type tableFacts struct {
	Name string
	// HasOrgID: the table carries an org_id column, so it holds tenant data
	// and every query against it needs a tenant predicate.
	HasOrgID bool
	// Forced: ALTER TABLE ... FORCE ROW LEVEL SECURITY was applied. FORCE
	// rather than ENABLE because the app connects as the table owner, for whom
	// plain ENABLE does nothing -- see migration v37.
	Forced bool
	// Origin is the migration version that created the table; CreatedOrgID the
	// one that gave it org_id. Reported by -census so a new table is easy to
	// place.
	Origin       int
	OrgIDVersion int
}

var (
	// Identifiers are PostgreSQL-style snake_case; schema-qualified names are
	// matched on their last segment, matching sqlcheck.go's extractTables.
	ident = `(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)`

	createTableRE = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + ident)
	dropTableRE   = regexp.MustCompile(`(?is)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?` + ident)
	renameTableRE = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+RENAME\s+TO\s+` + ident)
	addOrgIDRE    = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?"?org_id\b`)
	dropOrgIDRE   = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?"?org_id\b`)
	forceRLSRE    = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+FORCE\s+ROW\s+LEVEL\s+SECURITY`)
	noForceRLSRE  = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY`)
	disableRLSRE  = regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY`)

	orgIDColumnRE = regexp.MustCompile(`(?i)\borg_id\b`)
	lineCommentRE = regexp.MustCompile(`(?m)--[^\n]*`)
	blockCommentR = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// stripSQLComments blanks out -- and /* */ comments. Without it a migration
// header that explains a table in prose ("-- ai_agents has no org_id; scoping
// it is a separate effort", which sql_v43.go really does say) is read as DDL
// and the census learns the opposite of the truth.
func stripSQLComments(sql string) string {
	sql = blockCommentR.ReplaceAllString(sql, " ")
	return lineCommentRE.ReplaceAllString(sql, "")
}

// createdTableBody returns the parenthesised column list of the CREATE TABLE
// whose name ends at idx, and whether one was found. Balancing the parens is
// what a regex cannot do: a column list contains nested parens for types
// (VARCHAR(255)), defaults (gen_random_uuid()) and FK targets
// (REFERENCES organizations(id)), so "up to the first )" reads a fraction of
// the columns and misses an org_id declared after any of them.
func createdTableBody(sql string, idx int) (string, bool) {
	open := strings.IndexByte(sql[idx:], '(')
	if open < 0 {
		return "", false // CREATE TABLE ... AS SELECT, or a partition clause
	}
	i := idx + open
	depth, inQuote := 0, false
	for ; i < len(sql); i++ {
		c := sql[i]
		if inQuote {
			if c == '\'' {
				inQuote = false
			}
			continue
		}
		switch c {
		case '\'':
			inQuote = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return sql[idx+open : i+1], true
			}
		}
	}
	return "", false
}

// deriveCensus folds every migration's UpSQL, in version order, into one fact
// per live table. Down SQL is deliberately ignored: it describes the schema a
// rollback would produce, not the one the code runs against.
func deriveCensus(all []*migrations.Migration) map[string]*tableFacts {
	ordered := make([]*migrations.Migration, len(all))
	copy(ordered, all)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Version < ordered[j].Version })

	census := map[string]*tableFacts{}
	for _, m := range ordered {
		sql := stripSQLComments(m.UpSQL)

		for _, loc := range createTableRE.FindAllStringSubmatchIndex(sql, -1) {
			name := strings.ToLower(sql[loc[2]:loc[3]])
			t, ok := census[name]
			if !ok {
				t = &tableFacts{Name: name, Origin: m.Version}
				census[name] = t
			}
			// CREATE TABLE IF NOT EXISTS re-states a table an earlier
			// migration already created (v42/v45 do this deliberately for
			// installs whose schema came from init-db.sql). Only let it ADD
			// the fact, never retract one an ALTER established.
			if body, found := createdTableBody(sql, loc[1]); found && orgIDColumnRE.MatchString(body) && !t.HasOrgID {
				t.HasOrgID = true
				t.OrgIDVersion = m.Version
			}
		}

		for _, m2 := range addOrgIDRE.FindAllStringSubmatch(sql, -1) {
			name := strings.ToLower(m2[1])
			t, ok := census[name]
			if !ok {
				// A table created outside the registry (init-db.sql, a loose
				// .sql file) that a migration later scopes. It is real and it
				// holds tenant data, so it belongs in the census.
				t = &tableFacts{Name: name, Origin: m.Version}
				census[name] = t
			}
			if !t.HasOrgID {
				t.HasOrgID = true
				t.OrgIDVersion = m.Version
			}
		}
		for _, m2 := range dropOrgIDRE.FindAllStringSubmatch(sql, -1) {
			if t, ok := census[strings.ToLower(m2[1])]; ok {
				t.HasOrgID = false
				t.OrgIDVersion = 0
			}
		}

		for _, m2 := range forceRLSRE.FindAllStringSubmatch(sql, -1) {
			name := strings.ToLower(m2[1])
			if t, ok := census[name]; ok {
				t.Forced = true
			} else {
				census[name] = &tableFacts{Name: name, Origin: m.Version, Forced: true}
			}
		}
		for _, re := range []*regexp.Regexp{noForceRLSRE, disableRLSRE} {
			for _, m2 := range re.FindAllStringSubmatch(sql, -1) {
				if t, ok := census[strings.ToLower(m2[1])]; ok {
					t.Forced = false
				}
			}
		}

		for _, m2 := range renameTableRE.FindAllStringSubmatch(sql, -1) {
			from, to := strings.ToLower(m2[1]), strings.ToLower(m2[2])
			if t, ok := census[from]; ok {
				delete(census, from)
				t.Name = to
				census[to] = t
			}
		}
		for _, m2 := range dropTableRE.FindAllStringSubmatch(sql, -1) {
			delete(census, strings.ToLower(m2[1]))
		}
	}
	return census
}

// censusFindings splits the schema-level defects into the ones that block and
// the ones that are already on the register.
//
// blocking: a table in NO map. That is a table nobody has classified -- most
// likely one added since this ran last -- and it is the whole point of
// inverting the lint: the ISPM/AI tables were exactly this, and the old
// hand-maintained list reported nothing for nine releases. Failing here is
// what stops the class recurring.
//
// open: a table on needsScoping or needsBelt. Real findings, printed with
// their count on every run, but they predate this tool and fixing all of them
// is a migration programme, not a prerequisite for it. ddl_test.go pins both
// counts so the registers can only shrink.
func censusFindings(census map[string]*tableFacts) (blocking, open []Finding) {
	names := make([]string, 0, len(census))
	for n := range census {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		t := census[n]
		if !t.HasOrgID {
			if _, ok := installWideTables[n]; ok {
				continue
			}
			if why, ok := needsScoping[n]; ok {
				open = append(open, Finding{
					Table:  n,
					Reason: "on the needsScoping register: " + why,
					SQL:    sprintOrigin("created by migration v", t.Origin),
				})
				continue
			}
			blocking = append(blocking, Finding{
				Table: n,
				Reason: "no org_id and not classified -- give it org_id + FORCE RLS in a migration " +
					"if it holds tenant data, else declare it in installWideTables with a reason",
				SQL: sprintOrigin("created by migration v", t.Origin),
			})
			continue
		}
		if t.Forced {
			continue
		}
		if _, ok := beltExempt[n]; ok {
			continue
		}
		if why, ok := needsBelt[n]; ok {
			open = append(open, Finding{
				Table:  n,
				Reason: "on the needsBelt register (" + why + "): has org_id, no FORCE ROW LEVEL SECURITY",
				SQL:    sprintOrigin("org_id from migration v", t.OrgIDVersion),
			})
			continue
		}
		blocking = append(blocking, Finding{
			Table: n,
			Reason: "has org_id but no FORCE ROW LEVEL SECURITY and is not classified -- add the " +
				"belt in a migration, else declare it in beltExempt with a reason",
			SQL: sprintOrigin("org_id from migration v", t.OrgIDVersion),
		})
	}
	return blocking, open
}

// scopedFromCensus is the set sqlcheck.go asks its missing-predicate question
// about: every table that carries org_id AND whose boundary the database
// actually enforces.
//
// The needsBelt tables are deliberately left out. They carry org_id but have
// no FORCE ROW LEVEL SECURITY, which is already a reported finding at the
// table level; adding a line-level finding to every query against them would
// report the same root cause 148 more times and bury the ones that matter.
// This makes the ratchet self-closing: the moment a table's belt migration
// lands it leaves needsBelt, and every query against it comes under the lint
// in the same commit -- so the belt cannot be added without the predicates
// being checked.
func scopedFromCensus(census map[string]*tableFacts) map[string]bool {
	out := make(map[string]bool, len(census))
	for n, t := range census {
		if !t.HasOrgID {
			continue
		}
		if _, deferred := needsBelt[n]; deferred {
			continue
		}
		if _, deferred := predicateAuditPending[n]; deferred {
			continue
		}
		out[n] = true
	}
	return out
}

// sprintOrigin renders the "created by migration vNN" note carried on a census
// finding in place of SQL. Findings print their SQL field verbatim, so this
// keeps the one-line output shape identical for both kinds.
func sprintOrigin(prefix string, version int) string {
	if version == 0 {
		return prefix + "? (not created by a registered migration)"
	}
	return prefix + strconv.Itoa(version)
}
