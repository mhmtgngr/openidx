package access

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// The administrator's views of what a user can reach -- the user access map
// and the privilege graph, in both directions -- read every role and group
// membership row. A role (v223) or membership (v224) whose window had ended
// is not enforced any more, but stays until the expiry sweep deletes it, so
// the views showed access the user no longer had. The privilege graph said in
// its own comment that expired grants were excluded.
//
// On the migrated schema, one user holds a live and an ended role and a live
// and an ended group; a PAM entry and a vault secret are granted to each. The
// views show only what the live role and group give.
func TestTheAccessViewsShowOnlyLiveRolesAndMemberships(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	user := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "viewed-"+suffix)
	entries := map[string]string{} // entry id -> what grants it
	secrets := map[string]string{} // secret id -> what grants it
	for _, w := range []struct{ state, ends string }{{"live", "1 hour"}, {"ended", "-5 minutes"}} {
		name := w.state + "-" + suffix
		role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, name)
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, user, role, org, w.ends)
		group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, name)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, user, group, org, w.ends)
		for _, p := range []struct{ kind, id string }{{"role", role}, {"group", group}} {
			e := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, reach_mode)
				VALUES ($1, $2, 'ssh', 'host.example.test', 22, 'ziti') RETURNING id::text`, org, p.kind+"-"+name)
			scalar(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
				VALUES ($1, $2, $3, $4, ARRAY['connect']) RETURNING entry_id::text`, org, e, p.kind, p.id)
			entries[e] = w.state + " " + p.kind
		}
		sec := scalar(`INSERT INTO vault_secrets (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "secret-"+name)
		scalar(`INSERT INTO vault_access_grants (org_id, secret_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'role', $3, ARRAY['reveal']) RETURNING secret_id::text`, org, sec, role)
		secrets[sec] = w.state + " role"
	}
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}

	// The user access map.
	var iam AccessMapIAM
	if err := svc.collectIAMPillar(ctx, org, user, &iam); err != nil {
		t.Fatalf("collectIAMPillar: %v", err)
	}
	names := func(refs []NamedRef) []string {
		out := []string{}
		for _, r := range refs {
			out = append(out, r.Name)
		}
		return out
	}
	if got := names(iam.Roles); !slices.Equal(got, []string{"live-" + suffix}) {
		t.Errorf("the access map's roles = %v; want only the live role", got)
	}
	if got := names(iam.Groups); !slices.Equal(got, []string{"live-" + suffix}) {
		t.Errorf("the access map's groups = %v; want only the live group", got)
	}
	var pam AccessMapPAM
	if err := svc.collectPAMPillar(ctx, org, user, &pam); err != nil {
		t.Fatalf("collectPAMPillar: %v", err)
	}
	for _, g := range pam.VaultGrants {
		if secrets[g.SecretID] == "ended role" {
			t.Errorf("the access map lists the secret granted to the ended role")
		}
	}
	if len(pam.VaultGrants) != 1 {
		t.Errorf("the access map lists %d vault grants; want the live role's one", len(pam.VaultGrants))
	}

	// The privilege graph from the user.
	reach, err := svc.userReachableResources(ctx, user, "pam_entry_grants", "entry_id", "pam_entries", "pam_entry")
	if err != nil {
		t.Fatalf("userReachableResources: %v", err)
	}
	got := []string{}
	for _, r := range reach {
		got = append(got, entries[r.ID])
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"live group", "live role"}) {
		t.Errorf("the user's privilege graph reaches %v; want the live role's and the live group's entries", got)
	}

	// The privilege graph from each entry.
	for entry, what := range entries {
		rows, err := db.Pool.Query(ctx, reachSQL("pam_entry_grants", "entry_id"), entry)
		if err != nil {
			t.Fatalf("reachSQL: %v", err)
		}
		reached := false
		for rows.Next() {
			var r privReacher
			if err := rows.Scan(&r.UserID, &r.Username, &r.Via, &r.Path, &r.Actions); err != nil {
				t.Fatalf("scan a reacher: %v", err)
			}
			reached = reached || r.UserID == user
		}
		rows.Close()
		if want := what == "live role" || what == "live group"; reached != want {
			t.Errorf("the graph of the entry granted to the %s reaches the user: %v; want %v", what, reached, want)
		}
	}
}
