package migrations

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var createTableRe = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?`)
var dropTableRe = regexp.MustCompile(`(?i)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?`)

func tableNameSet(re *regexp.Regexp, sql string) map[string]bool {
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(sql, -1) {
		out[strings.ToLower(m[1])] = true
	}
	return out
}

// TestInitDBParity guards the recurring init-db<->migrations drift (P0-3): every
// table created by deployments/docker/init-db.sql must also be created by some
// versioned migration (or intentionally dropped by one). A table added to
// init-db.sql without a migration would 500 on managed-Postgres/RDS/Helm/migrate
// installs (which never run init-db.sql); this makes that a CI failure instead of
// a post-deploy 500.
func TestInitDBParity(t *testing.T) {
	// Go runs tests with the working directory set to the package dir
	// (internal/migrations), so init-db.sql is two levels up.
	data, err := os.ReadFile("../../deployments/docker/init-db.sql")
	if err != nil {
		t.Fatalf("read init-db.sql: %v", err)
	}
	initdb := tableNameSet(createTableRe, string(data))
	if len(initdb) < 150 {
		t.Fatalf("parsed only %d CREATE TABLE from init-db.sql; the regex is too strict — fix it before trusting this guard", len(initdb))
	}

	created, dropped := map[string]bool{}, map[string]bool{}
	for _, m := range allMigrations() {
		for n := range tableNameSet(createTableRe, m.UpSQL) {
			created[n] = true
		}
		for n := range tableNameSet(dropTableRe, m.UpSQL) {
			dropped[n] = true
		}
	}

	var missing []string
	for name := range initdb {
		if !created[name] && !dropped[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d table(s) in init-db.sql are created by NO migration "+
			"(init-db<->migrations drift — add them to a reconcile migration like sql_v54.go):\n%s",
			len(missing), strings.Join(missing, "\n"))
	}
}

// createTableBlockRe captures a table name and its parenthesised body. The body
// is non-greedy up to the closing ")" that sits on its own line before the ";",
// so column-level "NUMERIC(10,2)"-style parens don't terminate the match early.
var createTableBlockRe = regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?\s*\((.*?)\n\s*\)\s*;`)

// alterStmtRe captures a whole ALTER TABLE statement (table name + body up to the
// terminating ";"); addColRe then finds EVERY "ADD COLUMN <col>" inside it, so a
// comma-chained "ADD COLUMN a, ADD COLUMN b" is fully captured (not just the first).
var alterStmtRe = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?:[a-z_]\w*\.)?"?([a-z_]\w*)"?(.*?);`)
var addColRe = regexp.MustCompile(`(?is)ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_]\w*)"?`)

// constraintLeadKW are the leading tokens of a table-body line that is a
// constraint clause, not a column definition.
var constraintLeadKW = map[string]bool{
	"primary": true, "foreign": true, "unique": true,
	"constraint": true, "check": true, "exclude": true,
}

// tableColumns returns table -> set(column) parsed from every CREATE TABLE block
// and every ALTER TABLE ... ADD COLUMN in sql.
func tableColumns(sql string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	add := func(tbl, col string) {
		tbl, col = strings.ToLower(tbl), strings.ToLower(col)
		if out[tbl] == nil {
			out[tbl] = map[string]bool{}
		}
		out[tbl][col] = true
	}
	for _, m := range createTableBlockRe.FindAllStringSubmatch(sql, -1) {
		tbl := m[1]
		if out[strings.ToLower(tbl)] == nil {
			out[strings.ToLower(tbl)] = map[string]bool{}
		}
		for _, line := range strings.Split(m[2], "\n") {
			line = strings.TrimSpace(strings.TrimRight(strings.TrimSpace(line), ","))
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			first := strings.Trim(fields[0], `"`)
			lower := strings.ToLower(first)
			if constraintLeadKW[lower] {
				continue
			}
			if !regexp.MustCompile(`^[a-z_]\w*$`).MatchString(lower) {
				continue
			}
			add(tbl, first)
		}
	}
	for _, m := range alterStmtRe.FindAllStringSubmatch(sql, -1) {
		tbl := m[1]
		for _, c := range addColRe.FindAllStringSubmatch(m[2], -1) {
			add(tbl, c[1])
		}
	}
	return out
}

// TestInitDBColumnParity extends the table-level guard to columns: every column
// of an init-db.sql table that is ALSO created by a migration must itself be
// created by some migration (via CREATE TABLE or ALTER ... ADD COLUMN). This
// catches the class where a table exists in both sources but their column sets
// diverged (e.g. the historical ziti_certificates drift), which the table-only
// check missed — and which breaks migrate-only installs (RDS/Helm) that never
// run init-db.sql. Directional (init-db ⊆ migrations), matching the table-level
// guard: migration-only extra columns are harmless to init-db installs.
func TestInitDBColumnParity(t *testing.T) {
	data, err := os.ReadFile("../../deployments/docker/init-db.sql")
	if err != nil {
		t.Fatalf("read init-db.sql: %v", err)
	}
	initCols := tableColumns(string(data))
	if len(initCols) < 150 {
		t.Fatalf("parsed only %d CREATE TABLE blocks from init-db.sql; the block regex is too strict — fix it before trusting this guard", len(initCols))
	}

	migSQL := strings.Builder{}
	for _, m := range allMigrations() {
		migSQL.WriteString(m.UpSQL)
		migSQL.WriteString("\n")
	}
	migCols := tableColumns(migSQL.String())

	var drift []string
	for tbl, cols := range initCols {
		mc, ok := migCols[tbl]
		if !ok {
			// Table created by no migration — the table-level test reports this;
			// don't double-count here.
			continue
		}
		var miss []string
		for c := range cols {
			if !mc[c] {
				miss = append(miss, c)
			}
		}
		if len(miss) > 0 {
			sort.Strings(miss)
			drift = append(drift, tbl+": "+strings.Join(miss, ", "))
		}
	}
	if len(drift) > 0 {
		sort.Strings(drift)
		t.Errorf("%d table(s) have init-db.sql columns created by NO migration "+
			"(column-level init-db<->migrations drift — reconcile via an ALTER ... ADD COLUMN "+
			"migration like sql_v63.go):\n%s", len(drift), strings.Join(drift, "\n"))
	}
}
