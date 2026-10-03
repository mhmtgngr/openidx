package access

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/abac"
	"github.com/openidx/openidx/internal/appaccess"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
	"github.com/openidx/openidx/internal/pamgrant"
)

// A group membership an access request gave ends with the request (v224), and
// the expiry sweep deletes it within a minute. Until it does, the row is still
// there, so every reader that decides access has to read its window, as the
// role readers already read theirs. These did not:
//
//   - an application assigned to a group (appaccess, the proxy and OAuth);
//   - a PAM entry granted to a group: the launch check, and the sweep that
//     ends a session whose grant has gone;
//   - the access service's group ids for grant expansion, and its group names
//     for route authorization;
//   - the groups and roles ABAC reads for its subject;
//   - the group names the Ziti user sync turns into overlay attributes.
//
// On the migrated schema, one user holds a group whose window has passed and
// one that is live, and a role whose window has passed. Each reader must see
// the live group only, and no role.
func TestAnExpiredMembershipGrantsNothingBeforeTheSweep(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(ctx, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	octx := orgctx.WithBypassRLS(orgctx.With(ctx, orgctx.Org{ID: org}))
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...any) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(octx, q, args...).Scan(&v); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
		return v
	}
	user := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "windowed-"+suffix)
	group := func(name, ends string) string {
		id := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, name+"-"+suffix)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, user, id, org, ends)
		return id
	}
	ended := group("ended", "-5 minutes")
	live := group("live", "1 hour")
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, "ended-role-"+suffix)
	scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at)
		VALUES ($1, $2, $3, NOW() - interval '5 minutes') RETURNING user_id::text`, user, role, org)

	// Applications assigned to each group.
	app := func(name, groupID string) string {
		id := scalar(`INSERT INTO applications (org_id, client_id, name, type, enabled) VALUES ($1, $2, $2, 'web', true) RETURNING id::text`, org, name+"-"+suffix)
		scalar(`INSERT INTO group_application_assignments (org_id, group_id, application_id)
			VALUES ($1, $2, $3) RETURNING application_id::text`, org, groupID, id)
		return id
	}
	for _, tc := range []struct {
		app  string
		want bool
	}{{app("ended-app", ended), false}, {app("live-app", live), true}} {
		if got, err := appaccess.Allowed(octx, db, user, org, tc.app); err != nil || got != tc.want {
			t.Errorf("appaccess.Allowed for the %s group's application = %v, %v; want %v",
				map[bool]string{true: "live", false: "ended"}[tc.want], got, err, tc.want)
		}
	}

	// PAM entries granted to each group, and a live session on the ended one.
	entry := func(name, groupID string) string {
		id := scalar(`INSERT INTO pam_entries (org_id, name, entry_type, hostname, port, reach_mode)
			VALUES ($1, $2, 'ssh', $3, 22, 'ziti') RETURNING id::text`, org, name+"-"+suffix, name+".example.test")
		scalar(`INSERT INTO pam_entry_grants (org_id, entry_id, principal_type, principal_id, actions)
			VALUES ($1, $2, 'group', $3, ARRAY['connect']) RETURNING entry_id::text`, org, id, groupID)
		return id
	}
	endedEntry, liveEntry := entry("ended-entry", ended), entry("live-entry", live)
	if got, err := pamgrant.Holds(octx, db.Pool, org, endedEntry, user, nil, "connect"); err != nil || got {
		t.Errorf("pamgrant.Holds on the ended group's entry = %v, %v; want false", got, err)
	}
	if got, err := pamgrant.Holds(octx, db.Pool, org, liveEntry, user, nil, "connect"); err != nil || !got {
		t.Errorf("pamgrant.Holds on the live group's entry = %v, %v; want true", got, err)
	}
	endedSession := scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, status)
		VALUES ($1, $2, $3, 'ssh', 'active') RETURNING id::text`, org, endedEntry, user)
	liveSession := scalar(`INSERT INTO pam_entry_sessions (org_id, entry_id, user_id, protocol, status)
		VALUES ($1, $2, $3, 'ssh', 'active') RETURNING id::text`, org, liveEntry, user)
	lapsed, err := pamgrant.LapsedSessions(octx, db.Pool, 0, 1000)
	if err != nil {
		t.Fatalf("pamgrant.LapsedSessions: %v", err)
	}
	reasons := map[string]string{}
	for _, l := range lapsed {
		reasons[l.ID] = l.Reason
	}
	if reasons[endedSession] != "grant_ended" {
		t.Errorf("the session on the ended group's entry lapses as %q; want grant_ended", reasons[endedSession])
	}
	if r, ok := reasons[liveSession]; ok {
		t.Errorf("the session on the live group's entry lapses as %q; want it left running", r)
	}

	// The access service's own readers.
	svc := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	ids, err := svc.userGroupIDs(octx, org, user)
	if err != nil || !slices.Equal(ids, []string{live}) {
		t.Errorf("userGroupIDs = %v, %v; want only the live group", ids, err)
	}
	if names := svc.userGroupNames(octx, user); !slices.Equal(names, []string{"live-" + suffix}) {
		t.Errorf("userGroupNames = %v; want only the live group", names)
	}
	zm := &ZitiManager{cfg: &config.Config{}, logger: zap.NewNop(), db: db}
	if names, err := zm.getUserGroupNames(octx, user); err != nil || !slices.Equal(names, []string{"live-" + suffix}) {
		t.Errorf("the Ziti sync's group names = %v, %v; want only the live group", names, err)
	}

	// ABAC's subject.
	attrs, err := abac.SubjectAttributes(octx, db, user, org)
	if err != nil {
		t.Fatalf("abac.SubjectAttributes: %v", err)
	}
	if g, _ := attrs["groups"].([]string); !slices.Equal(g, []string{"live-" + suffix}) {
		t.Errorf("ABAC's subject groups = %v; want only the live group", attrs["groups"])
	}
	if r, _ := attrs["roles"].([]string); len(r) != 0 {
		t.Errorf("ABAC's subject roles = %v; want none, the only role's window has passed", r)
	}
}
