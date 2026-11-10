package migrations

import (
	"strings"
	"testing"
)

func TestMigrationV245RouteServiceAccountsShape(t *testing.T) {
	var mig *Migration
	for _, m := range allMigrations() {
		if m.Version == 245 {
			mig = m
		}
	}
	if mig == nil {
		t.Fatal("migration 245 is not registered")
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS proxy_route_service_accounts",
		"REFERENCES proxy_routes(id) ON DELETE CASCADE",
		"REFERENCES service_accounts(id) ON DELETE CASCADE",
		"org_id             UUID NOT NULL",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE  ROW LEVEL SECURITY",
		"current_setting('app.org_id', true)",
	} {
		if !strings.Contains(mig.UpSQL, want) {
			t.Errorf("v245 up lacks %q", want)
		}
	}
	if !strings.Contains(mig.DownSQL, "DROP TABLE IF EXISTS proxy_route_service_accounts") {
		t.Error("v245 down does not drop the table")
	}
}
