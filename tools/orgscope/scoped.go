package main

import "github.com/openidx/openidx/internal/migrations"

// The tenant-scope classification. Every table the migration DDL creates must
// land in exactly one of four states, and the tool decides three of them from
// the DDL itself (see ddl.go). These maps carry the human judgement the DDL
// cannot: whether a table WITHOUT org_id is correctly install-wide, and
// whether a table WITH org_id may go without the RLS belt.
//
// A reason is mandatory in every map. init() rejects a blank one, so an
// exception can never be added without saying why -- the same rule the
// //orgscope:ignore directive follows.
//
// The two "needs" registers below are open findings, not exemptions. They
// exist because inverting this lint turned an invisible problem into a
// counted one: the hand-maintained list this file replaced covered ~90
// tables, the schema has 231, and the difference was never checked by
// anything. Their sizes are pinned by ddl_test.go so they can only shrink;
// a table that is in NO map fails the build outright.

// installWideTables are tables with no org_id that correctly have none: they
// hold install configuration, a global catalog, infrastructure state, or the
// tenant registry itself.
var installWideTables = map[string]string{
	"organizations":        "the tenant registry itself",
	"organization_members": "join table; its column is organization_id, not org_id",
	"permissions":          "global permission-string catalog, identical for every tenant",
	"system_settings":      "install-wide configuration key/value",
	"error_catalog":        "global error-code catalog keyed by code; documentation, not data",
	"oauth_signing_keys":   "install-wide JWKS signing material (v79); one key set serves every tenant",
	"ip_threat_list":       "shared threat-intel feed consulted before a tenant is resolved",
	"ip_geolocation_cache": "shared IP->geo cache keyed by address; no tenant dimension",
	"posture_check_types":  "global enum of posture check kinds",
	"policy_sync_state":    "global governance->Ziti sync watermark",

	// Operations telemetry about the install, not about anyone's data.
	"health_check_history": "per-service dependency health for the operator; install-wide by design",
	"api_usage_metrics":    "endpoint/method/hour aggregate with no tenant dimension",

	// Ziti overlay infrastructure. The controller is a single install-wide
	// component; these mirror its state, and per-org overlay scoping is a
	// separate opt-in feature (ZITI_PER_ORG_ATTRIBUTES) that does not shard
	// the controller's own objects.
	"ziti_edge_routers":         "mirrors the Ziti controller's routers; controller-scoped infrastructure",
	"ziti_metrics":              "controller metrics",
	"ziti_ai_anomalies":         "controller-scoped anomaly detection over overlay identities (v110)",
	"ziti_ai_quarantine":        "controller-scoped quarantine state (v110)",
	"ziti_identity_activity":    "controller-scoped overlay activity rollup (v110)",
	"ziti_user_sync":            "single-row sync watermark for the controller identity sync",
	"ziti_browzer_config":       "one BrowZer/external-JWT-signer configuration per install",
	"usage_metering_cursor":     "single-row watermark for the metering roll-up job",
	"external_audit_sync_state": "single-row cursor for the outbound SIEM sync",
}

// beltExempt are org_id-carrying tables deliberately left out of the FORCE RLS
// belt. Each one is read or written on a path that has no tenant context yet,
// so a belt would fail the operation closed rather than scope it.
var beltExempt = map[string]string{
	"tenant_branding":     "read during tenant RESOLUTION, before app.org_id can be set (v38)",
	"tenant_domains":      "the table tenant resolution looks the host up in; belting it makes resolution impossible (v38)",
	"tenant_settings":     "read alongside tenant_domains during resolution (v38)",
	"ssf_stream_delivery": "outbox drained by a background worker that spans orgs (v99)",
	"ssf_received_events": "replay-dedup log of INBOUND SETs written by the public receiver endpoint, which carries no tenant context (v99)",
}

// needsScoping: OPEN FINDINGS. These tables hold per-user or per-org data and
// have no org_id, so today they are install-wide by construction -- the exact
// shape of the ISPM/AI defect that v138 fixed, in tables nobody had looked at
// because the old hand-maintained list could not see them. Each owes a
// migration (org_id + backfill + FORCE RLS) and an org predicate in its
// handlers. Listed with what the table actually holds so the batches are easy
// to cut.
//
// What is left is the DEFERRED half, and it is deferred on a product question
// rather than on effort. Both groups need a decision this lint cannot make:
//
//   - the external identity links: may one external account link to a user in
//     two tenants at once, and if so which tenant owns the link row?
//   - the agent fleet: three separate comments in internal/access assert that
//     the fleet is deliberately install-wide, so an agent id names a device
//     without naming a tenant. v159 raised this in the readiness guide as an
//     open product decision after finding that it leaves cross-tenant kiosk
//     TARGETING open with no tenant term available to close it.
//
// Every table on this register that did NOT need such a decision has now been
// scoped or dropped.
var needsScoping = map[string]string{
	// MFA and credentials — the most sensitive per-user rows in the product.
	"user_identity_links":  "per-user external identity links; needs the one-account-two-tenants decision",
	"social_account_links": "per-user social provider links; needs the one-account-two-tenants decision",

	// Agent fleet — the devices enrolled by a tenant's users.
	"enrolled_agents":         "enrolled devices with tokens and compliance state (v43); needs the is-the-fleet-per-tenant decision",
	"agent_posture_results":   "per-device posture results (v43); follows enrolled_agents",
	"agent_enrollment_tokens": "enrolment tokens that admit a device to the fleet (v43); follows enrolled_agents",
}

// needsBelt: OPEN FINDINGS. These carry org_id -- the application filters on
// it -- but never received FORCE ROW LEVEL SECURITY, so the database itself
// does not enforce the boundary and a single query that forgets its predicate
// crosses tenants silently. v37 belted the tables that existed then and v121
// extended it; everything added since has drifted out. Several of their own
// migrations say "org-scoped for RLS" while the belt was never applied.
//
// 34 -> 19. Migration v140 belted the fifteen whose queries this lint already
// proved carry their org predicate, so the belt could not change what any one
// of them returns. What is left is the harder half, and the count after each
// name says why: every one has at least one query that addresses a row by id
// without naming org_id, and by the ratchet in ddl.go those queries come under
// the missing-predicate rule the moment the belt lands. That coupling is
// deliberate -- belting a table and auditing its queries are the same act --
// so these leave in feature-sized batches together with their query fixes,
// never in one sweep.
var needsBelt = map[string]string{
	"report_exports":            "v26; 1 unscoped query",
	"device_trust_requests":     "v39; 2 unscoped queries",
	"oauth_registration_tokens": "v97; 3 unscoped queries",
	"oauth_device_codes":        "v125 redeemed by hashed device_code; confirm the pre-tenant path before belting; 4 unscoped queries",
	"enrollment_sessions":       "v132; 3 unscoped queries",
}

// predicateAuditPending: OPEN FINDINGS, query level. Deriving the scoped set
// from the DDL brought these tables under the missing-predicate rule for the
// first time, and 96 of their queries address rows by id without naming
// org_id.
//
// They are NOT live cross-tenant holes: every table here carries FORCE ROW
// LEVEL SECURITY, so a query that omits org_id is scoped by the database
// anyway, on the app.org_id the pool sets at checkout from orgctx. The
// predicate still matters -- a background job that opts into
// orgctx.WithBypassRLS loses the belt and keeps only what the SQL says -- so
// this is defence in depth worth having, not something to wave through. It is
// deferred rather than bulk-edited because adding 96 predicates blind is how
// a query gets a subtly wrong join, and each one wants reading.
//
// The register is pinned by ddl_test.go and can only shrink. A table leaves it
// by having its queries audited, not by being added to it.
var predicateAuditPending = map[string]string{
	"attestation_items":             "governance attestation",
	"attestation_campaigns":         "governance attestation",
	"certification_campaigns":       "governance certification",
	"campaign_runs":                 "governance certification",
	"request_approval_chains":       "governance approvals",
	"jit_grants":                    "governance JIT",
	"vault_secrets":                 "PAM vault",
	"vault_secret_versions":         "PAM vault",
	"vault_access_grants":           "PAM vault",
	"vault_checkouts":               "PAM vault",
	"credential_rotation_policies":  "PAM vault rotation",
	"guacamole_sessions":            "PAM session brokering",
	"guacamole_session_requests":    "PAM session brokering",
	"guacamole_moderation_sessions": "PAM session shadowing",
	"guacamole_users":               "PAM session brokering",
	"mcp_tool_approvals":            "MCP tool gating",
	"ssf_stream_delivery":           "SSF outbox, drained across orgs (also beltExempt)",
	"ssf_received_events":           "SSF inbound dedup log (also beltExempt)",
}

// census and scopedTables are derived once from the migration registry.
// scopedTables is what sqlcheck.go asks its missing-predicate question about,
// so that rule now covers every org_id-carrying table rather than the ~90
// someone remembered to type.
var (
	census       map[string]*tableFacts
	scopedTables map[string]bool
)

func init() {
	for name, m := range map[string]map[string]string{
		"installWideTables":     installWideTables,
		"beltExempt":            beltExempt,
		"needsScoping":          needsScoping,
		"needsBelt":             needsBelt,
		"predicateAuditPending": predicateAuditPending,
	} {
		for table, reason := range m {
			if reason == "" {
				panic("orgscope: " + name + "[" + table + "] has no reason; every entry must say why")
			}
		}
	}
	census = deriveCensus(migrations.All())
	scopedTables = scopedFromCensus(census)
}
