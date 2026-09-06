package main

// knownUnwritten is the backlog: tables the schema creates that no production
// code writes, each with the verdict from reading the code around it.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so an
// entry leaves only when the table gains a writer or the table goes.
//
// Two verdicts recur and they are not the same thing:
//
//   - "read, never written" is a measurement that cannot measure. A user is
//     shown a number derived from an empty table and has no way to tell it from
//     a measured zero. These are defects.
//   - "neither read nor written" is dead schema: DDL, indexes and grants for a
//     table no code has ever touched. Harmless to a running install, and a
//     standing invitation to write a query against a table that will never have
//     rows -- which is how the first kind is born.
var knownUnwritten = map[string]string{
	"ai_agent_activity": "the AI-agent registry has no runtime. Nothing outside internal/admin so much as reads ai_agent_credentials, so no agent ever acts through this product and there is no moment at which activity could be recorded. Three reads present the absence as measurement -- the per-agent activity list (LIMIT 100, always empty), the 24-hour top-agents ranking (every agent 0) and the recent-failures count (always 0). Recorded rather than fixed: what is missing is the agent runtime, and writing it is a feature.",

	"api_usage_metrics": "v54 created it with exactly the columns an hourly request aggregate needs -- (endpoint, method, service, status_code, count, avg_latency_ms, hour) and a UNIQUE on all but the counters -- and nothing has ever inserted a row. The Usage Analytics card reads it for total requests, top endpoints, error rate and average latency, so all four have read 0 on every install that has ever run. The read cannot succeed either: it names request_count, error_count and recorded_at, which the table does not have (see tools/sqlprepare).",

	"risk_factors": "v77 created it for the continuous-auth engine and the engine never writes it. CalculateSessionRisk computes five weighted factors, sums them into a score, and returns RiskFactors as the empty slice it was initialised with; the history INSERT stores the literal '{}' in session_risks.risk_factors, discarding the detail it just computed. The table's only reader, GetRiskFactors, has no caller at all. So the API field named risk_factors is empty on every response, and the stored history cannot say why any score was what it was.",

	"upstream_pools": "v130 built the place to express a load-balanced backend set -- algorithm, hash key, active health checks, per-node weights -- and the reconciler that renders it into the data plane. Nothing builds the other half: no handler, no route, no console page can create a pool, so proxy_routes.upstream_pool_id is NULL on every route on every install and loadUpstreamPools returns an empty map every time. Recorded rather than fixed: the missing half is a CRUD surface with its own console page, which is a feature.",

	"upstream_pool_members": "the members of the pools above. Same verdict: the reconciler reads them, nothing can create them.",

	"health_check_history": "v54's per-service dependency-health history (service_name, dependency_name, status, latency_ms, checked_at) with an index for the time-series read someone intended. Neither written nor read. The health checks that do exist (internal/access/health_checks.go) report live and store nothing.",

	"posture_check_types": "v29's global enum of posture check kinds. deployments/docker/seed.sql fills it with five rows and no Go code has ever read it: posture check definitions live in Go (internal/admin's postureCheckDefs), which is why the ISPM rules page works at all. Dead schema plus a seed that maintains it.",

	"scim_groups": "the unused half of v3's SCIM pair. scim_users is written and updated by the provisioning service on every SCIM user operation; group provisioning writes the product's own groups table (internal/provisioning/service.go), and scim_groups has never had a writer. Its install-wide UNIQUE on display_name was re-scoped by an earlier commit in this programme -- a constraint fixed on a table nothing uses.",

	"user_mfa_policies": "v5's per-user MFA policy table. No writer, no reader, and no history of either: MFA policy is decided by admin_console_settings (the security key) and the per-factor tables. Dead schema.",
}
