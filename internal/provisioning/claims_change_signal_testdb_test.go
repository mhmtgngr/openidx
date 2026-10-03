package provisioning

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/ssfsignal"
	"github.com/openidx/openidx/internal/migrations"
)

// A SCIM group push and a provisioning rule tell the tenant's SSF receivers
// when they change a user's groups or roles (CAEP token-claims-change), once
// per user, and say nothing about a user whose memberships they left as they
// were. On the migrated schema:
//
//   - a group created with members tells each member;
//   - a push that replaces the members tells the ones it added and the ones
//     it dropped, and not the ones it kept;
//   - deleting the group tells its members;
//   - a rule that adds a group or a role tells the user once, and a second
//     run that changes nothing says nothing.
func TestSCIMAndRuleChangesTellTheReceivers(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()
	bg := context.Background()
	if err := migrations.NewMigrator(db.Pool.Raw(), zap.NewNop()).MigrateTo(bg, -1); err != nil {
		t.Fatalf("migrate to latest: %v", err)
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
		return scalar(`INSERT INTO users (org_id, username, email, enabled) VALUES ($1, $2::text, $2::text || '@example.test', true) RETURNING id::text`,
			org, name+"-"+suffix)
	}
	reasons := func(userID string) string {
		return scalar(`SELECT COALESCE(string_agg(claims->>'reason', ',' ORDER BY id), '') FROM ssf_pending_events
			WHERE subject_id = $1 AND event_type = $2 AND org_id = $3`, userID, ssfsignal.TokenClaimsChange, org)
	}
	svc := NewService(db, nil, &config.Config{}, zap.NewNop())

	kept, dropped, added := user("cs-kept"), user("cs-dropped"), user("cs-added")
	name := "cs-group-" + suffix
	created, err := svc.CreateSCIMGroup(ctx, &SCIMGroup{DisplayName: name, Members: []SCIMMember{{Value: kept}, {Value: dropped}}})
	if err != nil {
		t.Fatalf("create the group: %v", err)
	}
	if _, err := svc.UpdateSCIMGroup(ctx, created.ID, &SCIMGroup{DisplayName: name, Members: []SCIMMember{{Value: kept}, {Value: added}}}); err != nil {
		t.Fatalf("push the group: %v", err)
	}
	if err := svc.DeleteSCIMGroup(ctx, created.ID); err != nil {
		t.Fatalf("delete the group: %v", err)
	}

	ruled := user("cs-ruled")
	roleName := "cs-role-" + suffix
	scalar(`INSERT INTO roles (org_id, name, description) VALUES ($1, $2, '') RETURNING id::text`, org, roleName)
	ruleGroup := "cs-rule-group-" + suffix
	scalar(`INSERT INTO groups (org_id, name) VALUES ($1, $2) RETURNING id::text`, org, ruleGroup)
	for run := 0; run < 2; run++ {
		svc.applyRuleAction(ctx, org, ruled, RuleAction{Type: "add_to_group", Target: ruleGroup}, "cs-rule")
		svc.applyRuleAction(ctx, org, ruled, RuleAction{Type: "assign_role", Target: roleName}, "cs-rule")
	}

	for _, c := range []struct{ who, userID, want string }{
		{"a member the push kept", kept, "scim.CreateSCIMGroup,scim.DeleteSCIMGroup"},
		{"a member the push dropped", dropped, "scim.CreateSCIMGroup,scim.UpdateSCIMGroup"},
		{"a member the push added", added, "scim.UpdateSCIMGroup,scim.DeleteSCIMGroup"},
		{"a user two rules changed, run twice", ruled, "provisioning rule add_to_group,provisioning rule assign_role"},
	} {
		if got := reasons(c.userID); got != c.want {
			t.Errorf("%s: token-claims-change reasons %q, want %q", c.who, got, c.want)
		}
	}
}
