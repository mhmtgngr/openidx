package main

import (
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/migrations"
)

// formerHandList is scoped.go as it stood before the census replaced it: the
// ~90 table names someone had remembered to type. It is kept here as a pin.
// Deriving the set from the DDL must never LOSE a table the hand list had --
// that would be a silent coverage regression, the same failure mode in the
// opposite direction from the one that let ispm_* and ai_agents through.
var formerHandList = []string{
	"access_request_approvals",
	"access_requests",
	"access_reviews",
	"ai_agent_activity",
	"ai_agent_credentials",
	"ai_agent_permissions",
	"ai_agents",
	"ai_recommendations",
	"api_keys",
	"application_sso_settings",
	"applications",
	"approval_policies",
	"audit_events",
	"compliance_reports",
	"composite_roles",
	"credential_rotations",
	"data_subject_requests",
	"device_posture_results",
	"directory_integrations",
	"directory_sync_logs",
	"directory_sync_state",
	"email_verification_tokens",
	"group_join_requests",
	"group_memberships",
	"groups",
	"identity_providers",
	"ispm_findings",
	"ispm_rules",
	"ispm_scores",
	"known_devices",
	"login_history",
	"mfa_backup_codes",
	"mfa_policies",
	"mfa_push_challenges",
	"mfa_push_devices",
	"mfa_totp",
	"mfa_webauthn",
	"notification_preferences",
	"notifications",
	"oauth_access_tokens",
	"oauth_authorization_codes",
	"oauth_clients",
	"oauth_refresh_tokens",
	"pam_entries",
	"pam_entry_access_requests",
	"pam_entry_favorites",
	"pam_entry_grants",
	"pam_entry_sessions",
	"pam_folders",
	"password_history",
	"password_reset_tokens",
	"policies",
	"policy_rules",
	"posture_checks",
	"privacy_assessments",
	"privacy_retention_policies",
	"provisioning_rules",
	"proxy_routes",
	"proxy_sessions",
	"qr_login_sessions",
	"recommendation_history",
	"recording_retention_policies",
	"review_items",
	"risk_factors",
	"role_permissions",
	"roles",
	"scim_groups",
	"scim_users",
	"security_alerts",
	"service_accounts",
	"session_risks",
	"sessions",
	"ssf_streams",
	"stepup_challenges",
	"user_application_assignments",
	"user_consents",
	"user_invitations",
	"user_mfa_policies",
	"user_roles",
	"user_sessions",
	"users",
	"webhook_deliveries",
	"webhook_subscriptions",
	"ziti_certificates",
	"ziti_identities",
	"ziti_service_policies",
	"ziti_services",
}

func TestDerivedSetCoversFormerHandList(t *testing.T) {
	for _, table := range formerHandList {
		if scopedTables[table] {
			continue
		}
		// A former-list table may legitimately have left the query rule only
		// by landing on a register -- and then the register entry is the
		// record of it. Anything else is lost coverage.
		if why, ok := needsBelt[table]; ok {
			t.Errorf("%s was on the hand list and is now only on needsBelt (%s); "+
				"the hand list enforced its queries, so keep it in the query rule", table, why)
			continue
		}
		if why, ok := predicateAuditPending[table]; ok {
			t.Logf("%s deferred to predicateAuditPending (%s)", table, why)
			continue
		}
		if _, ok := census[table]; !ok {
			t.Errorf("%s was on the hand list but no migration creates it", table)
			continue
		}
		t.Errorf("%s was on the hand list and is now unchecked by any rule", table)
	}
}

// --- census derivation -----------------------------------------------------

func mig(v int, up string) *migrations.Migration {
	return &migrations.Migration{Version: v, Name: "fixture", UpSQL: up, DownSQL: "-- none"}
}

func TestCensusReadsOrgIDFromCreateTable(t *testing.T) {
	c := deriveCensus([]*migrations.Migration{
		mig(1, `CREATE TABLE widgets (id UUID PRIMARY KEY, org_id UUID NOT NULL);`),
		mig(2, `CREATE TABLE gadgets (id UUID PRIMARY KEY, name TEXT);`),
	})
	if !c["widgets"].HasOrgID {
		t.Error("widgets declares org_id in its column list but the census missed it")
	}
	if c["gadgets"].HasOrgID {
		t.Error("gadgets has no org_id but the census thinks it does")
	}
}

// The trap that makes a regex insufficient: a column list contains nested
// parens for types, defaults and FK targets, so reading "up to the first )"
// stops at VARCHAR(255) and never sees the org_id declared after it.
func TestCensusBalancesParensInColumnList(t *testing.T) {
	c := deriveCensus([]*migrations.Migration{
		mig(1, `CREATE TABLE widgets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
			org_id UUID NOT NULL REFERENCES organizations(id)
		);`),
	})
	if !c["widgets"].HasOrgID {
		t.Error("org_id declared after a VARCHAR(255) and a REFERENCES users(id) was not seen")
	}
}

// The other trap: sql_v43.go's own header says in prose that ai_agents has no
// org_id. Read as DDL, a comment teaches the census the opposite of the truth.
func TestCensusIgnoresComments(t *testing.T) {
	c := deriveCensus([]*migrations.Migration{
		mig(1, `-- CREATE TABLE ghosts (id UUID, org_id UUID);
			/* ALTER TABLE widgets ADD COLUMN org_id UUID; */
			CREATE TABLE widgets (id UUID PRIMARY KEY);`),
	})
	if _, ok := c["ghosts"]; ok {
		t.Error("a CREATE TABLE inside a -- comment was read as DDL")
	}
	if c["widgets"].HasOrgID {
		t.Error("an ALTER TABLE inside a block comment was read as DDL")
	}
}

func TestCensusFollowsAlterAddAndDrop(t *testing.T) {
	c := deriveCensus([]*migrations.Migration{
		mig(1, `CREATE TABLE widgets (id UUID PRIMARY KEY);
			CREATE TABLE doomed (id UUID PRIMARY KEY);
			CREATE TABLE renamed_from (id UUID PRIMARY KEY, org_id UUID);`),
		mig(2, `ALTER TABLE widgets ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
			ALTER TABLE widgets FORCE  ROW LEVEL SECURITY;
			DROP TABLE IF EXISTS doomed;
			ALTER TABLE renamed_from RENAME TO renamed_to;`),
	})
	if !c["widgets"].HasOrgID || !c["widgets"].Forced {
		t.Errorf("widgets = %+v, want org_id and the belt", c["widgets"])
	}
	if c["widgets"].OrgIDVersion != 2 {
		t.Errorf("widgets OrgIDVersion = %d, want 2", c["widgets"].OrgIDVersion)
	}
	if _, ok := c["doomed"]; ok {
		t.Error("a dropped table is still in the census")
	}
	if _, ok := c["renamed_from"]; ok {
		t.Error("a renamed table is still under its old name")
	}
	if !c["renamed_to"].HasOrgID {
		t.Error("a renamed table lost its facts")
	}
}

// A migration that re-states an existing table with CREATE TABLE IF NOT EXISTS
// (v42 and v45 do this for installs whose schema came from init-db.sql) must
// not retract an org_id an earlier ALTER established.
func TestCensusIfNotExistsDoesNotRetractOrgID(t *testing.T) {
	c := deriveCensus([]*migrations.Migration{
		mig(1, `CREATE TABLE widgets (id UUID PRIMARY KEY);`),
		mig(2, `ALTER TABLE widgets ADD COLUMN org_id UUID;`),
		mig(3, `CREATE TABLE IF NOT EXISTS widgets (id UUID PRIMARY KEY);`),
	})
	if !c["widgets"].HasOrgID {
		t.Error("CREATE TABLE IF NOT EXISTS retracted an org_id an ALTER had added")
	}
}

// --- the rules -------------------------------------------------------------

// withEmptyRegisters runs f with the four classification maps emptied, so a
// fixture census is judged on its own rather than against the real schema.
func withEmptyRegisters(t *testing.T, f func()) {
	t.Helper()
	iw, be, ns, nb := installWideTables, beltExempt, needsScoping, needsBelt
	installWideTables = map[string]string{}
	beltExempt = map[string]string{}
	needsScoping = map[string]string{}
	needsBelt = map[string]string{}
	defer func() { installWideTables, beltExempt, needsScoping, needsBelt = iw, be, ns, nb }()
	f()
}

// This is the whole point of the inversion: a table nobody classified must
// fail, because that is exactly what ispm_findings and ai_agents were.
func TestUndeclaredTableIsBlocking(t *testing.T) {
	withEmptyRegisters(t, func() {
		c := deriveCensus([]*migrations.Migration{
			mig(1, `CREATE TABLE mystery (id UUID PRIMARY KEY, user_id UUID);`),
		})
		blocking, open := censusFindings(c)
		if len(blocking) != 1 || blocking[0].Table != "mystery" {
			t.Fatalf("blocking = %v, want exactly the unclassified table", blocking)
		}
		if len(open) != 0 {
			t.Errorf("open = %v, want none", open)
		}
		if !strings.Contains(blocking[0].SQL, "v1") {
			t.Errorf("finding does not name the origin migration: %s", blocking[0].SQL)
		}
	})
}

func TestDeclaredInstallWideIsClean(t *testing.T) {
	withEmptyRegisters(t, func() {
		installWideTables["mystery"] = "a reason"
		c := deriveCensus([]*migrations.Migration{mig(1, `CREATE TABLE mystery (id UUID PRIMARY KEY);`)})
		if blocking, open := censusFindings(c); len(blocking)+len(open) != 0 {
			t.Errorf("declared install-wide table still reported: %v %v", blocking, open)
		}
	})
}

func TestOrgIDWithoutBeltIsBlocking(t *testing.T) {
	withEmptyRegisters(t, func() {
		c := deriveCensus([]*migrations.Migration{
			mig(1, `CREATE TABLE widgets (id UUID PRIMARY KEY, org_id UUID NOT NULL);`),
		})
		blocking, _ := censusFindings(c)
		if len(blocking) != 1 || !strings.Contains(blocking[0].Reason, "FORCE ROW LEVEL SECURITY") {
			t.Fatalf("blocking = %v, want the missing-belt finding", blocking)
		}
	})
}

func TestBeltedTableIsClean(t *testing.T) {
	withEmptyRegisters(t, func() {
		c := deriveCensus([]*migrations.Migration{
			mig(1, `CREATE TABLE widgets (id UUID PRIMARY KEY, org_id UUID NOT NULL);
				ALTER TABLE widgets FORCE  ROW LEVEL SECURITY;`),
		})
		if blocking, open := censusFindings(c); len(blocking)+len(open) != 0 {
			t.Errorf("a scoped, belted table was reported: %v %v", blocking, open)
		}
	})
}

// A register entry reports but does not block: the backlog predates the tool.
func TestRegisteredTablesReportWithoutBlocking(t *testing.T) {
	withEmptyRegisters(t, func() {
		needsScoping["mystery"] = "holds per-user rows"
		needsBelt["widgets"] = "v1"
		c := deriveCensus([]*migrations.Migration{
			mig(1, `CREATE TABLE mystery (id UUID PRIMARY KEY);
				CREATE TABLE widgets (id UUID PRIMARY KEY, org_id UUID NOT NULL);`),
		})
		blocking, open := censusFindings(c)
		if len(blocking) != 0 {
			t.Errorf("register entries must not block: %v", blocking)
		}
		if len(open) != 2 {
			t.Errorf("open = %d findings, want 2 (one per register entry)", len(open))
		}
	})
}

// --- the registers can only shrink ----------------------------------------

// These pins are the reason the registers are honest rather than a dumping
// ground: adding a table to one fails here, so the only way to make a new
// finding go away is to fix it.
func TestRegistersOnlyShrink(t *testing.T) {
	for _, c := range []struct {
		name string
		got  int
		max  int
	}{
		// 61 -> 58: migration v141 scoped the admin audit log and the audit
		// archives. Re-pinned so the register cannot grow back. 50 -> 45 with
		// v145, which took the five credentials that stand in for a password:
		// hardware_tokens, hardware_token_events, mfa_bypass_codes,
		// mfa_bypass_audit and magic_links.
		{"needsScoping", len(needsScoping), 45},
		// 34 → 19: migration v140 belted the fifteen whose queries already
		// carried their org predicate. Re-pinned rather than left at 34, or
		// the register could grow back into the room the fix just made.
		{"needsBelt", len(needsBelt), 19},
		{"predicateAuditPending", len(predicateAuditPending), 18},
		{"installWideTables", len(installWideTables), 21},
		{"beltExempt", len(beltExempt), 5},
	} {
		if c.got > c.max {
			t.Errorf("%s has %d entries, was %d: a register may only shrink. "+
				"Fix the table (migration + predicates) instead of declaring it.", c.name, c.got, c.max)
		}
	}
}

// Every classification carries a reason, in every map. init() panics on a
// blank one; this proves the maps as committed satisfy it and that no entry
// is a bare name.
func TestEveryClassificationHasAReason(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"installWideTables":     installWideTables,
		"beltExempt":            beltExempt,
		"needsScoping":          needsScoping,
		"needsBelt":             needsBelt,
		"predicateAuditPending": predicateAuditPending,
	} {
		for table, reason := range m {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s[%q] has no reason", name, table)
			}
		}
	}
}

// A table must not be classified twice -- two reasons for one table means one
// of them is stale, and which rule applies becomes an accident of ordering.
func TestNoTableIsClassifiedTwice(t *testing.T) {
	seen := map[string]string{}
	for name, m := range map[string]map[string]string{
		"installWideTables": installWideTables,
		"beltExempt":        beltExempt,
		"needsScoping":      needsScoping,
		"needsBelt":         needsBelt,
	} {
		for table := range m {
			if prev, dup := seen[table]; dup {
				t.Errorf("%s is in both %s and %s", table, prev, name)
			}
			seen[table] = name
		}
	}
}

// The real schema must be fully classified: this is the assertion that goes
// red the day someone adds a table and forgets.
func TestRealSchemaIsFullyClassified(t *testing.T) {
	blocking, _ := censusFindings(census)
	for _, f := range blocking {
		t.Errorf("unclassified table %q: %s (%s)", f.Table, f.Reason, f.SQL)
	}
}
