package main

// knownBroken is the backlog: statements PostgreSQL has already refused, each
// with the verdict from reading it against the schema the migrations create.
//
// Keys are the file plus a hash of the statement's normalized text. Moving a
// query down a file keeps its entry; EDITING the query does not, because an
// edited query has to be re-verified -- which is the behaviour wanted from a
// list whose whole purpose is to stop being needed.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so the
// only way an entry leaves is the query being fixed. Line numbers in the
// comments are from the sweep that seeded it and are not used for matching.
var knownBroken = map[string]string{
	// internal/access/browzer_config.go:350  [42883] function unnest(jsonb) does not exist
	"internal/access/browzer_config.go#8871328c5b6e": "browzer_targets.paths is JSONB and the query calls unnest() on it; the BrowZer path list is never expanded, so the generated nginx config loses per-path rules.",

	// internal/access/unified_audit.go:179  [42P01] missing FROM-clause entry for table "e"
	"internal/access/unified_audit.go#a2103cfa5d45": "the statement references alias \"e\" that its own FROM clause does not define; the unified audit export returns an error the caller discards.",

	// internal/admin/analytics_enhanced.go:358  [42703] column "revoked_at" does not exist
	"internal/admin/analytics_enhanced.go#589305fb4b37": "api_keys records revocation in `status`, not a revoked_at column; the api_keys feature-adoption figure is always 0. This one at least logs the failure.",

	// internal/admin/predictive_analytics.go:241  [42703] column u.last_login does not exist
	"internal/admin/predictive_analytics.go#5948c3dee70a": "users has last_login_at, not last_login; the churn/growth prediction input is never read.",

	// internal/admin/service.go:2960  [42703] column "last_login" does not exist
	"internal/admin/service.go#fc94058888bf": "users.last_login_at again, spelled last_login.",

	// internal/admin/tenant_branding.go:401  [42703] column "display_name" does not exist
	"internal/admin/tenant_branding.go#f8bf19c05cb9": "organizations has `name`, not display_name; branding falls back to the default for every tenant.",

	// internal/admin/tenant_branding.go:437  [42703] column o.display_name does not exist
	"internal/admin/tenant_branding.go#1936085a63fc": "same column, qualified as o.display_name.",

	// internal/audit/anomaly.go:337  [42703] column "resource_type" does not exist
	"internal/audit/anomaly.go#44c7545bd70d": "the anomaly sweep groups by a resource_type column the audit table does not have; that detector never fires.",

	// internal/audit/compliance.go:273  [42703] column "due_date" does not exist
	"internal/audit/compliance.go#ac03bc8e4d2f": "the control-status query selects due_date from a table without it; the compliance dashboard shows no due dates.",

	// internal/audit/compliance.go:424  [42703] column "created_at" does not exist
	"internal/audit/compliance.go#0901156ab63d": "created_at absent on that relation; the evidence-age computation never runs.",

	// internal/audit/compliance.go:699  [42703] column "resource_type" does not exist
	"internal/audit/compliance.go#0b9ef89fdfeb": "resource_type absent; the access-evidence section is empty.",

	// internal/audit/compliance_enhanced.go:391  [42703] column "revoked_at" does not exist
	"internal/audit/compliance_enhanced.go#9bc12472e453": "api_keys revocation is `status`; the expired-key control reports 0 findings, which reads as compliant.",

	// internal/audit/compliance_enhanced.go:394  [42703] column "revoked_at" does not exist
	"internal/audit/compliance_enhanced.go#489ea4acfc82": "api_keys revocation is `status`; this is the second query of the same expired-key control, so both halves of it report nothing.",

	// internal/audit/compliance_enhanced.go:858  [42703] column "created_at" does not exist
	"internal/audit/compliance_enhanced.go#de460d4ce663": "created_at absent on that relation; the evidence bundle omits the section.",

	// internal/governance/service.go:495  [42803] column "ar.id" must appear in the GROUP BY clause or be used in an aggregate function
	"internal/governance/service.go#d3a7d5f31586": "an aggregate query selects ar.id without grouping by it; the campaign roll-up never runs.",

	// internal/identity/biometric.go:414  [42703] column "roles" does not exist
	"internal/identity/biometric.go#4960f8b6b383": "roles are a join table, not a users column; the biometric policy's role predicate is never evaluated.",

	// internal/identity/handlers_analytics.go:368  [42804] COALESCE types character varying and uuid cannot be matched
	"internal/identity/handlers_analytics.go#8ece3113ceb3": "COALESCE across varchar and uuid cannot resolve; the analytics query fails at plan time.",

	// internal/identity/pushmfa_enroll.go:63  [42883] operator does not exist: uuid = text
	"internal/identity/pushmfa_enroll.go#1b48d783cd3a": "a uuid column is compared to a text parameter with no cast; push-MFA enrolment lookup errors.",

	// internal/identity/service.go:6377  [42703] column "created_at" of relation "user_roles" does not exist
	"internal/identity/service.go#7fed18af736e": "user_roles has assigned_at, not created_at; the role-history read fails.",

	// internal/oauth/saml_metadata.go:378  [42703] column "metadata_xml" of relation "saml_service_providers" does not exist
	"internal/oauth/saml_metadata.go#3ecaefc538a0": "saml_service_providers stores metadata under a different column; the SAML SP metadata refresh writes nothing.",

	// internal/risk/scoring_engine.go:562  [42703] column "created_at" does not exist
	"internal/risk/scoring_engine.go#74a403735d1d": "created_at absent on that relation; the scoring engine's history window is never read.",
}
