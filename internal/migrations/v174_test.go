package migrations

import (
	"os"
	"strings"
	"testing"
)

// TestMigrationV174_securityAlertColumns pins the four columns security_alerts
// gained, and — more usefully — pins that the writer and the schema now agree.
//
// The defect this migration closes is not a missing column, it is a statement
// and a table that disagreed for the whole life of the feature with nothing to
// notice: internal/risk/alert.go named six columns the table never had, so the
// INSERT always failed, always returned an error the caller logged, and no
// security alert was ever persisted on any install.
func TestMigrationV174_securityAlertColumns(t *testing.T) {
	m := migrationByVersion(t, 174)
	if m.Name != "security_alert_columns" {
		t.Errorf("v174 Name = %q, want security_alert_columns", m.Name)
	}

	added := []string{"user_agent", "deliveries", "acknowledged_by", "acknowledged_at"}
	for _, col := range added {
		if !strings.Contains(m.UpSQL, "ADD COLUMN IF NOT EXISTS "+col) {
			t.Errorf("v174 UpSQL does not add security_alerts.%s", col)
		}
		if !strings.Contains(m.DownSQL, "DROP COLUMN IF EXISTS "+col) {
			t.Errorf("v174 DownSQL does not drop security_alerts.%s", col)
		}
	}

	// No NOT NULL and no backfill: the table is empty by construction, because
	// its only writer never succeeded. A NOT NULL here would be a claim about
	// rows that cannot exist.
	if strings.Contains(m.UpSQL, "SET NOT NULL") {
		t.Error("v174 sets NOT NULL on a column with no backfill")
	}
}

// The two writers must name only columns that exist. tools/sqlprepare proves
// this against a real database in the integration job; this checks the source
// so the package's own test suite fails on a reintroduction, without a DB.
func TestSecurityAlertWritersNameOnlyRealColumns(t *testing.T) {
	// Every column security_alerts has, from the v-era CREATE TABLE plus what
	// migrations added since. Kept here rather than derived because the derived
	// version already exists and runs where a database does.
	columns := map[string]bool{
		"id": true, "org_id": true, "user_id": true, "alert_type": true,
		"severity": true, "status": true, "title": true, "description": true,
		"details": true, "source_ip": true, "remediation_actions": true,
		"resolved_by": true, "resolved_at": true, "created_at": true,
		"updated_at": true,
		// added by v174
		"user_agent": true, "deliveries": true,
		"acknowledged_by": true, "acknowledged_at": true,
	}

	for _, file := range []string{"../risk/alert.go", "../audit/anomaly.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, cols := range insertColumnLists(string(src), "security_alerts") {
			for _, col := range cols {
				if !columns[col] {
					t.Errorf("%s: INSERT INTO security_alerts names %q, which the table does not have",
						file, col)
				}
			}
		}
	}
}

// insertColumnLists returns the parenthesised column list of every
// `INSERT INTO <table> (...)` in src.
func insertColumnLists(src, table string) [][]string {
	var out [][]string
	needle := "INSERT INTO " + table
	for i := 0; ; {
		j := strings.Index(src[i:], needle)
		if j < 0 {
			return out
		}
		i += j + len(needle)
		open := strings.Index(src[i:], "(")
		close := strings.Index(src[i:], ")")
		if open < 0 || close < 0 || close < open {
			continue
		}
		var cols []string
		for _, f := range strings.Split(src[i+open+1:i+close], ",") {
			if f = strings.TrimSpace(f); f != "" {
				cols = append(cols, f)
			}
		}
		out = append(out, cols)
	}
}

func migrationByVersion(t *testing.T, version int) *Migration {
	t.Helper()
	for _, cand := range allMigrations() {
		if cand.Version == version {
			return cand
		}
	}
	t.Fatalf("migration v%d not registered in allMigrations()", version)
	return nil
}

// TestMigrationV175_siemForwardCursor pins that the cursor lives in the chain
// and that the runtime DDL is gone.
//
// The forwarder created this table itself, through a pool that connects as
// openidx_app -- a role v53 created without DDL rights on the schema. So the
// CREATE always failed and every poll after it failed on a missing relation.
// A table created by application code is a table the owner role never makes,
// orgscope never sees and a restore never recreates.
func TestMigrationV175_siemForwardCursor(t *testing.T) {
	m := migrationByVersion(t, 175)
	if m.Name != "siem_forward_cursor" {
		t.Errorf("v175 Name = %q, want siem_forward_cursor", m.Name)
	}
	for _, frag := range []string{
		"CREATE TABLE IF NOT EXISTS siem_forward_cursor",
		"INSERT INTO siem_forward_cursor (id) VALUES (1) ON CONFLICT (id) DO NOTHING",
		"GRANT SELECT, INSERT, UPDATE ON siem_forward_cursor TO openidx_app",
	} {
		if !strings.Contains(m.UpSQL, frag) {
			t.Errorf("v175 UpSQL missing: %q", frag)
		}
	}
	// The forwarder needs no DELETE on a singleton, and a grant wider than the
	// need is the thing least-privilege exists to stop.
	if strings.Contains(m.UpSQL, "DELETE ON siem_forward_cursor") {
		t.Error("v175 grants DELETE on a single-row cursor")
	}

	src, err := os.ReadFile("../audit/siem_forwarder.go")
	if err != nil {
		t.Fatalf("read forwarder: %v", err)
	}
	if strings.Contains(string(src), "CREATE TABLE") {
		t.Error("the forwarder still creates schema at runtime; openidx_app cannot, " +
			"so the statement fails and every poll after it fails on a missing relation")
	}
}
