package governance

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/migrations"
)

// A role or a group membership an access request gave ends with its window
// (v223, v224), and the expiry sweep deletes the row within a minute. Until it
// does, governance counted it in two places that decide who may do what:
//
//   - a role or group approval step named its holders as approvers, so a user
//     whose approver role had ended could still be asked, and decide;
//   - auto-approve's allowed_roles and allowed_groups conditions held for a
//     requester whose role or group had ended, so the request skipped its
//     approvers.
//
// On the migrated schema: the steps name only the live holder, and the
// conditions hold only for a live role or group.
func TestAnEndedRoleOrGroupNeitherApprovesNorAutoApproves(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, "approvers-"+suffix)
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "approver-group-"+suffix)
	hold := func(userID, ends string) {
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, userID, role, org, ends)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at)
			VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`, userID, group, org, ends)
	}
	ended, live, requester := user("ended-approver"), user("live-approver"), user("requester")
	hold(ended, "-5 minutes")
	hold(live, "1 hour")

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	for _, step := range []ApprovalStep{
		{Order: 1, Type: ApprovalStepTypeRole, RoleID: role},
		{Order: 1, Type: ApprovalStepTypeGroup, GroupID: group},
	} {
		got, err := s.resolveStepApprovers(ctx, org, step, requester)
		if err != nil || !slices.Equal(got, []string{live}) {
			t.Errorf("a %s step's approvers = %v, %v; want only the live holder %s", step.Type, got, err, live)
		}
	}

	for _, tc := range []struct {
		what      string
		requester string
		cond      AutoApproveConditions
		want      bool
	}{
		{"an ended role", ended, AutoApproveConditions{AllowedRoles: []string{"approvers-" + suffix}}, false},
		{"a live role", live, AutoApproveConditions{AllowedRoles: []string{"approvers-" + suffix}}, true},
		{"an ended group", ended, AutoApproveConditions{AllowedGroups: []string{"approver-group-" + suffix}}, false},
		{"a live group", live, AutoApproveConditions{AllowedGroups: []string{"approver-group-" + suffix}}, true},
	} {
		cond := tc.cond
		if got := s.autoApproveConditionsMet(ctx, org, tc.requester, &cond); got != tc.want {
			t.Errorf("auto-approve for a requester with %s = %v; want %v", tc.what, got, tc.want)
		}
	}
}

// The SoD detective reads what each user holds and reports a pair of
// conflicting roles or groups as a violation. It read every row, so a role or
// membership whose window had ended -- held by nobody any more, but not yet
// deleted by the expiry sweep -- could still be reported in a conflict. On the
// migrated schema, a user's assignments are the live role and group only.
func TestTheSoDDetectiveReadsOnlyLiveAssignments(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const org = "00000000-0000-0000-0000-000000000010"
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	user := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
		org, "sod-held-"+suffix)
	for _, w := range []struct{ name, ends string }{{"sod-live-" + suffix, "1 hour"}, {"sod-ended-" + suffix, "-5 minutes"}} {
		role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, w.name+"-role")
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval)
			RETURNING user_id::text`, user, role, org, w.ends)
		group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, w.name+"-group")
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval)
			RETURNING user_id::text`, user, group, org, w.ends)
	}

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	held, err := s.loadUserAssignments(ctx, org)
	if err != nil {
		t.Fatalf("loadUserAssignments: %v", err)
	}
	got := []string{}
	for name := range held[user] {
		got = append(got, name)
	}
	slices.Sort(got)
	if want := []string{"sod-live-" + suffix + "-group", "sod-live-" + suffix + "-role"}; !slices.Equal(got, want) {
		t.Errorf("the SoD detective's assignments for the user = %v; want %v", got, want)
	}
}

// The entitlement warehouse and the privileged-account discovery snapshot
// what each user holds. Both read every row, so a role or membership whose
// window had ended was snapshotted as held until the expiry sweep deleted it;
// and both treated a group membership as standing, though v224 gave
// memberships a window. On the migrated schema, with users holding live,
// time-bound and ended admin roles and groups:
//
//   - the warehouse has the live role and group, each with its window, and
//     neither ended one;
//   - discovery finds the users holding a live privileged role or group, marks
//     standing only the one whose membership has no window, and does not find
//     the user whose only privilege has ended.
func TestTheSnapshotsReadOnlyLiveAssignments(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(ctx, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	// A fresh organization, so the snapshots hold only this test's rows.
	org := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "snap-"+suffix)
	octx := orgctx.With(ctx, orgctx.Org{ID: org})
	user := func(name string) string {
		return scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`,
			org, name+"-"+suffix)
	}
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, "admin-"+suffix)
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "sudoers-"+suffix)
	timed, standingMember, ended := user("snap-timed"), user("snap-standing"), user("snap-ended")
	scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + interval '1 hour') RETURNING user_id::text`, timed, role, org)
	scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() - interval '5 minutes') RETURNING user_id::text`, ended, role, org)
	scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + interval '1 hour') RETURNING user_id::text`, timed, group, org)
	scalar(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1, $2, $3) RETURNING user_id::text`, standingMember, group, org)
	scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() - interval '5 minutes') RETURNING user_id::text`, ended, group, org)

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	if _, err := s.RunEntitlementRebuild(octx, org); err != nil {
		t.Fatalf("RunEntitlementRebuild: %v", err)
	}
	rows := map[string]string{}
	r, err := db.Pool.Query(octx, `SELECT user_id::text, entitlement_type, time_bound FROM entitlement_warehouse
		WHERE org_id = $1 AND entitlement_type IN ('role','group')`, org)
	if err != nil {
		t.Fatalf("read the warehouse: %v", err)
	}
	for r.Next() {
		var u, typ string
		var timeBound bool
		if err := r.Scan(&u, &typ, &timeBound); err != nil {
			t.Fatalf("scan: %v", err)
		}
		rows[u+" "+typ] = fmt.Sprint(timeBound)
	}
	r.Close()
	for _, c := range []struct{ key, want string }{
		{timed + " role", "true"}, {timed + " group", "true"}, {standingMember + " group", "false"},
		{ended + " role", ""}, {ended + " group", ""},
	} {
		if got := rows[c.key]; got != c.want {
			t.Errorf("warehouse row %q time_bound = %q; want %q (empty: no row)", c.key, got, c.want)
		}
	}

	if _, err := s.RunPrivilegedDiscovery(octx, org); err != nil {
		t.Fatalf("RunPrivilegedDiscovery: %v", err)
	}
	found := map[string]string{}
	r, err = db.Pool.Query(octx, `SELECT user_id::text, standing_privilege FROM privileged_accounts_discovered WHERE org_id = $1`, org)
	if err != nil {
		t.Fatalf("read discovery: %v", err)
	}
	for r.Next() {
		var u string
		var standing bool
		if err := r.Scan(&u, &standing); err != nil {
			t.Fatalf("scan: %v", err)
		}
		found[u] = fmt.Sprint(standing)
	}
	r.Close()
	for _, c := range []struct{ who, user, want string }{
		{"the time-bound holder", timed, "false"}, {"the standing member", standingMember, "true"}, {"the ended holder", ended, ""},
	} {
		if got := found[c.user]; got != c.want {
			t.Errorf("discovery of %s: standing %q; want %q (empty: not found)", c.who, got, c.want)
		}
	}
}

// An access review is generated from what users hold: their roles, the roles
// they reach through composites, their groups, and their privileged roles.
// Each generator read every row, so a reviewer was asked to certify a role or
// membership whose window had ended -- held by nobody any more, but not yet
// deleted by the expiry sweep. On the migrated schema, each generator turns a
// live assignment into an item and leaves an ended one out.
func TestAReviewIsGeneratedFromLiveAssignmentsOnly(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	scalar := func(q string, args ...interface{}) string {
		t.Helper()
		var v string
		if err := db.Pool.QueryRow(bg, q, args...).Scan(&v); err != nil {
			t.Fatalf("(%s): %v", q, err)
		}
		return v
	}
	// A fresh organization, so each review holds only this test's rows.
	org := scalar(`INSERT INTO organizations (name, slug) VALUES ($1, $1) RETURNING id::text`, "review-"+suffix)
	ctx := orgctx.With(bg, orgctx.Org{ID: org})
	live := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`, org, "rv-live-"+suffix)
	ended := scalar(`INSERT INTO users (org_id, username, email) VALUES ($1, $2::text, $2::text || '@example.test') RETURNING id::text`, org, "rv-ended-"+suffix)
	role := scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, 'admin', '') RETURNING id::text`, org)
	group := scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, "rv-group-"+suffix)
	for _, h := range []struct{ user, ends string }{{live, "1 hour"}, {ended, "-5 minutes"}} {
		scalar(`INSERT INTO user_roles (user_id, role_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`,
			h.user, role, org, h.ends)
		scalar(`INSERT INTO group_memberships (user_id, group_id, org_id, expires_at) VALUES ($1, $2, $3, NOW() + $4::interval) RETURNING user_id::text`,
			h.user, group, org, h.ends)
	}

	s := &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}
	for _, g := range []struct {
		name string
		run  func(context.Context, pgx.Tx, string) error
	}{
		{"user access", s.populateUserAccessItems},
		{"role assignment", s.populateRoleAssignmentItems},
		{"application access", s.populateApplicationAccessItems},
		{"privileged access", s.populatePrivilegedAccessItems},
	} {
		review := scalar(`INSERT INTO access_reviews (name, type, start_date, end_date, org_id)
			VALUES ($1, 'user_access', NOW(), NOW() + interval '1 day', $2) RETURNING id::text`, g.name+"-"+suffix, org)
		tx, err := db.Pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := g.run(ctx, tx, review); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("%s: %v", g.name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		count := func(userID string) string {
			return scalar(`SELECT count(*)::text FROM review_items WHERE review_id = $1 AND user_id = $2`, review, userID)
		}
		if got := count(live); got == "0" {
			t.Errorf("the %s review has no item for the live assignment", g.name)
		}
		if got := count(ended); got != "0" {
			t.Errorf("the %s review has %s item(s) for the ended assignment; want none", g.name, got)
		}
	}
}
