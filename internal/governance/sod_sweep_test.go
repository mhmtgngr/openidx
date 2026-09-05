package governance

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
)

// The detective half of separation of duties.
//
// evaluateSoDPolicy blocks a REQUEST that would create a toxic combination.
// RunSoDSweep is what finds the combinations that already exist — the control
// an SOX/ISAE/DORA audit actually asks to see — and its whole value is in what
// it does on the second run: refresh what is still true, close what is not, and
// never quietly close something that is.

const (
	sodOrgA  = "00000000-0000-0000-0000-0000000000a0"
	sodOrgB  = "00000000-0000-0000-0000-0000000000b0"
	sodUser  = "00000000-0000-0000-0000-0000000000a1"
	sodOther = "00000000-0000-0000-0000-0000000000b1"
)

const sodSchema = `
CREATE TABLE IF NOT EXISTS organizations (id UUID PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY, username TEXT, email TEXT, org_id UUID, enabled BOOLEAN DEFAULT TRUE);
CREATE TABLE IF NOT EXISTS roles  (id UUID PRIMARY KEY, name TEXT, org_id UUID);
CREATE TABLE IF NOT EXISTS groups (id UUID PRIMARY KEY, name TEXT, org_id UUID);
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID, role_id UUID, org_id UUID, assigned_by UUID, PRIMARY KEY (user_id, role_id));
CREATE TABLE IF NOT EXISTS group_memberships (
    user_id UUID, group_id UUID, org_id UUID, PRIMARY KEY (user_id, group_id));
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY, name TEXT, type TEXT, enabled BOOLEAN DEFAULT TRUE, org_id UUID);
CREATE TABLE IF NOT EXISTS policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    rule_type TEXT, conditions JSONB NOT NULL, actions JSONB, org_id UUID);
CREATE TABLE IF NOT EXISTS sod_violations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL,
    policy_id         UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    policy_name       VARCHAR(255),
    user_id           UUID NOT NULL,
    conflicting_roles TEXT[] NOT NULL DEFAULT '{}',
    status            VARCHAR(16) NOT NULL DEFAULT 'open',
    detail            TEXT,
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ,
    resolved_by       UUID,
    notes             TEXT,
    UNIQUE (org_id, policy_id, user_id)
);`

type sodFixture struct {
	svc *Service
	ctx context.Context
	t   *testing.T
}

func newSoDFixture(t *testing.T) *sodFixture {
	t.Helper()

	db, cleanup := setupTestDB(t)
	if db == nil {
		t.SkipNow()
	}
	t.Cleanup(cleanup)

	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, sodSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	f := &sodFixture{svc: &Service{db: db, config: &config.Config{}, logger: zap.NewNop()}, ctx: ctx, t: t}
	for _, org := range []string{sodOrgA, sodOrgB} {
		f.exec(`INSERT INTO organizations (id, name) VALUES ($1, $2)`, org, org)
	}
	f.exec(`INSERT INTO users (id, username, org_id) VALUES ($1,'alice',$2)`, sodUser, sodOrgA)
	f.exec(`INSERT INTO users (id, username, org_id) VALUES ($1,'bob',$2)`, sodOther, sodOrgB)
	return f
}

func (f *sodFixture) exec(sql string, args ...interface{}) {
	f.t.Helper()
	if _, err := f.svc.db.Pool.Exec(f.ctx, sql, args...); err != nil {
		f.t.Fatalf("exec %q: %v", sql, err)
	}
}

// policy registers an enabled separation_of_duty policy whose one rule names
// the given conflicting assignment names.
func (f *sodFixture) policy(id, org, name string, conflicting []string, enabled bool) {
	f.t.Helper()
	f.exec(`INSERT INTO policies (id, name, type, enabled, org_id) VALUES ($1,$2,'separation_of_duty',$3,$4)`,
		id, name, enabled, org)
	f.exec(`INSERT INTO policy_rules (policy_id, rule_type, conditions, actions, org_id)
	        VALUES ($1,'sod',jsonb_build_object('conflicting_roles', $2::jsonb),'{}'::jsonb,$3)`,
		id, jsonArray(conflicting), org)
}

func jsonArray(names []string) string {
	out := "["
	for i, n := range names {
		if i > 0 {
			out += ","
		}
		out += `"` + n + `"`
	}
	return out + "]"
}

func (f *sodFixture) grantRole(user, org, roleID, roleName string) {
	f.t.Helper()
	f.exec(`INSERT INTO roles (id, name, org_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, roleID, roleName, org)
	f.exec(`INSERT INTO user_roles (user_id, role_id, org_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, user, roleID, org)
}

func (f *sodFixture) revokeRole(user, roleID string) {
	f.t.Helper()
	f.exec(`DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, user, roleID)
}

func (f *sodFixture) joinGroup(user, org, groupID, groupName string) {
	f.t.Helper()
	f.exec(`INSERT INTO groups (id, name, org_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, groupID, groupName, org)
	f.exec(`INSERT INTO group_memberships (user_id, group_id, org_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, user, groupID, org)
}

type violationRow struct {
	status          string
	detail          string
	notes           string
	firstDetectedAt time.Time
	lastDetectedAt  time.Time
	resolvedAt      *time.Time
}

func (f *sodFixture) violation(org, policyID, user string) (violationRow, bool) {
	f.t.Helper()
	var v violationRow
	var notes *string
	err := f.svc.db.Pool.QueryRow(f.ctx, `
		SELECT status, COALESCE(detail,''), notes, first_detected_at, last_detected_at, resolved_at
		  FROM sod_violations WHERE org_id=$1 AND policy_id=$2 AND user_id=$3`,
		org, policyID, user).Scan(&v.status, &v.detail, &notes, &v.firstDetectedAt, &v.lastDetectedAt, &v.resolvedAt)
	if err != nil {
		return violationRow{}, false
	}
	if notes != nil {
		v.notes = *notes
	}
	return v, true
}

func (f *sodFixture) sweep(org string) *SoDSweepResult {
	f.t.Helper()
	res, err := f.svc.RunSoDSweep(f.ctx, org)
	if err != nil {
		f.t.Fatalf("sweep: %v", err)
	}
	return res
}

const (
	polA    = "00000000-0000-0000-0000-0000000000c1"
	polB    = "00000000-0000-0000-0000-0000000000c2"
	rolePay = "00000000-0000-0000-0000-0000000000d1"
	roleApv = "00000000-0000-0000-0000-0000000000d2"
	grpApv  = "00000000-0000-0000-0000-0000000000d3"
)

// --------------------------------------------------------------------------

// The base case, and the one that would break first if the sweep's own clock
// disagreed with the database's: a violation this sweep just recorded must not
// be closed by the same sweep's auto-resolve pass.
func TestSoDSweepRecordsAConflictAndLeavesItOpen(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Pay and approve", []string{"payments", "approvals"}, true)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")

	res := f.sweep(sodOrgA)
	if res.PoliciesEvaluated != 1 || res.ViolationsFound != 1 || res.NewViolations != 1 {
		t.Fatalf("result = %+v, want 1 policy / 1 violation / 1 new", res)
	}
	if res.AutoResolved != 0 {
		t.Errorf("the sweep auto-resolved %d violation(s) it had just recorded", res.AutoResolved)
	}

	v, ok := f.violation(sodOrgA, polA, sodUser)
	if !ok {
		t.Fatal("no violation row written")
	}
	if v.status != "open" {
		t.Errorf("status = %q, want open", v.status)
	}
	if v.detail != "holds conflicting: approvals + payments" {
		t.Errorf("detail = %q; it should name the combination, sorted", v.detail)
	}
}

// A second sweep with nothing changed refreshes the row rather than creating a
// duplicate or counting it as new: the register is a state of the world, not a
// log of sweeps.
func TestSoDSweepIsIdempotent(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Pay and approve", []string{"payments", "approvals"}, true)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")

	first := f.sweep(sodOrgA)
	before, _ := f.violation(sodOrgA, polA, sodUser)

	second := f.sweep(sodOrgA)
	if second.NewViolations != 0 {
		t.Errorf("second sweep reported %d new violations, want 0", second.NewViolations)
	}
	if second.ViolationsFound != first.ViolationsFound {
		t.Errorf("violations found changed between identical sweeps: %d then %d",
			first.ViolationsFound, second.ViolationsFound)
	}
	after, _ := f.violation(sodOrgA, polA, sodUser)
	if !after.lastDetectedAt.After(before.lastDetectedAt) {
		t.Errorf("last_detected_at did not move: %v then %v", before.lastDetectedAt, after.lastDetectedAt)
	}
	if !after.firstDetectedAt.Equal(before.firstDetectedAt) {
		t.Errorf("first_detected_at moved; the age of a finding is what an auditor reads")
	}
}

// Remediation closes the finding, and a recurrence reopens the SAME row so its
// history — when it was first seen — survives.
func TestSoDSweepAutoResolvesAndReopens(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Pay and approve", []string{"payments", "approvals"}, true)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")
	f.sweep(sodOrgA)
	opened, _ := f.violation(sodOrgA, polA, sodUser)

	// Someone takes the conflicting role away.
	f.revokeRole(sodUser, roleApv)
	res := f.sweep(sodOrgA)
	if res.AutoResolved != 1 {
		t.Fatalf("auto-resolved %d, want 1", res.AutoResolved)
	}
	v, _ := f.violation(sodOrgA, polA, sodUser)
	if v.status != "resolved" || v.resolvedAt == nil {
		t.Fatalf("status=%q resolved_at=%v, want resolved with a timestamp", v.status, v.resolvedAt)
	}

	// And it comes back.
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")
	res = f.sweep(sodOrgA)
	if res.NewViolations != 0 {
		t.Errorf("a reopened violation counted as new; its history would restart")
	}
	v, _ = f.violation(sodOrgA, polA, sodUser)
	if v.status != "open" {
		t.Errorf("status = %q, want open on recurrence", v.status)
	}
	if v.resolvedAt != nil {
		t.Errorf("resolved_at = %v on a reopened violation, want NULL", v.resolvedAt)
	}
	if !v.firstDetectedAt.Equal(opened.firstDetectedAt) {
		t.Errorf("first_detected_at moved on reopen; the finding's age is its history")
	}
	// The note the auto-resolve left said the conflict was gone. On a reopened,
	// live violation that reads as a contradiction to whoever reviews the
	// register, so the reopen has to say so too.
	if !strings.Contains(v.notes, "reopened") {
		t.Errorf("notes = %q; a reopened row still claims 'conflict no longer present' and says nothing about the recurrence", v.notes)
	}
}

// A waiver is a decision someone made and signed for. The sweep may refresh it
// but must never close it, or the exception disappears from the register the
// next time the conflict is momentarily absent.
func TestSoDSweepNeverTouchesAWaivedViolation(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Pay and approve", []string{"payments", "approvals"}, true)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")
	f.sweep(sodOrgA)
	f.exec(`UPDATE sod_violations SET status='waived', notes='approved by CFO' WHERE user_id=$1`, sodUser)

	// Conflict gone: an open violation would be auto-resolved here.
	f.revokeRole(sodUser, roleApv)
	res := f.sweep(sodOrgA)
	if res.AutoResolved != 0 {
		t.Errorf("auto-resolved %d; a waiver is not the sweep's to close", res.AutoResolved)
	}
	v, _ := f.violation(sodOrgA, polA, sodUser)
	if v.status != "waived" {
		t.Errorf("status = %q, want waived", v.status)
	}
	if v.notes != "approved by CFO" {
		t.Errorf("notes = %q, want the waiver's own note untouched", v.notes)
	}
}

// 'acknowledged' means someone has seen it and is working on it. The conflict
// is still real, so the sweep refreshes the row and leaves the status alone.
func TestSoDSweepKeepsAnAcknowledgedViolationAcknowledged(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Pay and approve", []string{"payments", "approvals"}, true)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")
	f.sweep(sodOrgA)
	f.exec(`UPDATE sod_violations SET status='acknowledged' WHERE user_id=$1`, sodUser)

	f.sweep(sodOrgA)
	v, _ := f.violation(sodOrgA, polA, sodUser)
	if v.status != "acknowledged" {
		t.Errorf("status = %q, want acknowledged while the conflict persists", v.status)
	}
}

// Conflicts are expressed as assignment NAMES, and an assignment can be a role
// or a group. A policy that names one of each must still fire, or the whole
// control is avoidable by granting the second half through a group.
func TestSoDSweepMatchesGroupsAndRolesTogether(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Pay and approve", []string{"Payments", "APPROVALS"}, true)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.joinGroup(sodUser, sodOrgA, grpApv, "Approvals")

	res := f.sweep(sodOrgA)
	if res.ViolationsFound != 1 {
		t.Fatalf("found %d violations; a role plus a group is still a conflict, and the match is case-insensitive", res.ViolationsFound)
	}
}

// A disabled policy is a policy an operator turned off. A disabled user is not
// holding anything. Neither should produce findings.
func TestSoDSweepSkipsDisabledPoliciesAndUsers(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Off", []string{"payments", "approvals"}, false)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")

	if res := f.sweep(sodOrgA); res.PoliciesEvaluated != 0 || res.ViolationsFound != 0 {
		t.Fatalf("a disabled policy produced %+v", res)
	}

	f.exec(`UPDATE policies SET enabled = true WHERE id=$1`, polA)
	f.exec(`UPDATE users SET enabled = false WHERE id=$1`, sodUser)
	if res := f.sweep(sodOrgA); res.ViolationsFound != 0 {
		t.Fatalf("a disabled user produced %d violations", res.ViolationsFound)
	}
}

// The sweep is per organization, and the auto-resolve pass is an UPDATE over
// sod_violations — the shape that has crossed tenants elsewhere in this
// codebase. One org's sweep must not read, write or close another's.
func TestSoDSweepStaysInsideItsOrganization(t *testing.T) {
	f := newSoDFixture(t)
	f.policy(polA, sodOrgA, "Pay and approve", []string{"payments", "approvals"}, true)
	f.policy(polB, sodOrgB, "Pay and approve", []string{"payments", "approvals"}, true)
	f.grantRole(sodUser, sodOrgA, rolePay, "payments")
	f.grantRole(sodUser, sodOrgA, roleApv, "approvals")
	f.grantRole(sodOther, sodOrgB, "00000000-0000-0000-0000-0000000000e1", "payments")
	f.grantRole(sodOther, sodOrgB, "00000000-0000-0000-0000-0000000000e2", "approvals")

	f.sweep(sodOrgA)
	f.sweep(sodOrgB)
	if _, ok := f.violation(sodOrgB, polB, sodOther); !ok {
		t.Fatal("precondition: org B must have its own violation")
	}

	// Org A remediates and sweeps. Org B's violation is untouched by it.
	f.revokeRole(sodUser, roleApv)
	res := f.sweep(sodOrgA)
	if res.AutoResolved != 1 {
		t.Fatalf("org A auto-resolved %d, want 1", res.AutoResolved)
	}
	if res.UsersScanned != 1 {
		t.Errorf("org A scanned %d users; org B's user is not its business", res.UsersScanned)
	}
	v, ok := f.violation(sodOrgB, polB, sodOther)
	if !ok {
		t.Fatal("org B's violation disappeared during org A's sweep")
	}
	if v.status != "open" {
		t.Errorf("org B's violation is %q after org A's sweep, want open", v.status)
	}
}
