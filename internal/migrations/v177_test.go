package migrations

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v177's four tables were never read and never written. What this pins is the
// rollback, because that is the part a reviewer cannot check by eye: two of
// them acquired org_id, a foreign key, an index and an RLS policy long after
// their original DDL, and scim_groups' unique key was re-scoped by v173, so a
// Down built from the creating migration would roll back to a schema this
// repository has not shipped in a long time.
func TestMigrationV177_dropsTheFourOrphans(t *testing.T) {
	m := migrationByVersion(t, 177)
	if m.Name != "drop_orphan_tables" {
		t.Errorf("v177 Name = %q, want drop_orphan_tables", m.Name)
	}

	for _, table := range []string{
		"health_check_history", "posture_check_types", "scim_groups", "user_mfa_policies",
	} {
		if !strings.Contains(m.UpSQL, "DROP TABLE IF EXISTS "+table) {
			t.Errorf("v177 UpSQL does not drop %s", table)
		}
		if !strings.Contains(m.DownSQL, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Errorf("v177 DownSQL does not recreate %s", table)
		}
	}

	// The two behind the v37 belt come back belted. A recreated table with
	// org_id and no policy is a tenant boundary that only looks maintained.
	for _, table := range []string{"scim_groups", "user_mfa_policies"} {
		for _, frag := range []string{
			"CREATE POLICY pol_" + table + "_org_scope ON " + table,
			"ALTER TABLE " + table + " FORCE  ROW LEVEL SECURITY",
			"fk_" + table + "_org",
		} {
			if !strings.Contains(m.DownSQL, frag) {
				t.Errorf("v177 DownSQL missing %q", frag)
			}
		}
	}

	// v173 re-scoped this key; the rollback must restore that shape, not v3's
	// install-wide UNIQUE.
	if !strings.Contains(m.DownSQL, "idx_scim_groups_org_display_name ON scim_groups(org_id, display_name)") {
		t.Error("v177 DownSQL restores the pre-v173 install-wide unique key on scim_groups")
	}
	if strings.Contains(m.DownSQL, "display_name VARCHAR(255) UNIQUE") {
		t.Error("v177 DownSQL recreates scim_groups with the install-wide UNIQUE v173 removed")
	}
}

// The seed that maintained rows nobody consulted goes with the table it filled.
// A seed naming a dropped table fails `docker compose up` on a fresh install,
// which is the first command in the README.
func TestV177SeedNoLongerFillsADroppedTable(t *testing.T) {
	seed, err := os.ReadFile(filepath.Join("..", "..", "deployments", "docker", "seed.sql"))
	if err != nil {
		t.Fatalf("read seed.sql: %v", err)
	}
	for _, table := range []string{
		"health_check_history", "posture_check_types", "scim_groups", "user_mfa_policies",
	} {
		if strings.Contains(string(seed), table) {
			t.Errorf("deployments/docker/seed.sql still names %s, which v177 drops", table)
		}
	}
}
