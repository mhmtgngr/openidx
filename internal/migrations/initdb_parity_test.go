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
