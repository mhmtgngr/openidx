package main

// knownDead is the backlog: service types with a constructor no binary calls
// and not one reachable method. Each carries the verdict from reading the code
// around it -- what it looks like it does, what actually happens, and whether
// the answer is to wire it or delete it.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so an
// entry leaves only when the service is wired or deleted.
//
// Three verdicts recur, and they are not the same thing:
//
//   - A SECOND IMPLEMENTATION. The product does the job somewhere else, with
//     different semantics. The dead one is what a reader finds first, and it is
//     where a well-meaning fix lands. Delete.
//   - A FEATURE THAT LOOKS SHIPPED. Nothing else does the job. It has tests,
//     sometimes migrations, sometimes a published claim in the documentation.
//     It is absent from the product, and saying so is the whole point of the
//     entry. Wire it, or withdraw the claim.
//   - AN ABSTRACTION NOBODY ADOPTED. A cache layer, a middleware registry, a
//     storage interface written before the thing that would use it. Harmless
//     until someone reads it as the house pattern. Delete.
var knownDead = map[string]string{
	// ---- audit -------------------------------------------------------------
	//
	// audit.AuditEvent and audit.Logger used to head this list: the
	// tamper-evident HMAC hash chain the docs index, the architecture page, the
	// audit reference page and the README's readiness checklist all advertise,
	// implemented in full and reachable from nothing, with no column in any
	// migration to store a hash in. Migration v181 and internal/audit/chain.go
	// closed it -- the sealer chains each org's rows and
	// GET /api/v1/audit/chain/verify answers whether the trail is intact -- so
	// both entries left this register the way an entry is supposed to.

	"internal/audit.AnomalyDetector": "brute-force and suspicious-pattern detection over audit events, with per-principal failed-login trackers and a DetectorConfig of thresholds. Nothing constructs it and no route exposes it. The live risk signals are elsewhere and unrelated: internal/admin/continuous_auth.go scores IP change, device and behaviour, and internal/risk scores logins. A SECOND IMPLEMENTATION of a job the product already does, minus the audit-event corpus this one would have read. Delete, or fold its thresholds into internal/risk.",

	// ---- auth --------------------------------------------------------------
	//
	// auth.TokenService, auth.SessionService and auth.RBACMiddleware stood
	// here: JWT mint/validate/revoke, Redis sessions with a concurrency cap,
	// and gin RBAC enforcement, each constructed only by its own tests. All
	// three are deleted -- the live equivalents are internal/oauth (tokens,
	// sessions and the per-client concurrency policy) and each service's own
	// auth middleware.
	//
	// One of them was load-bearing in the worst way. auth.UserRevocationKey
	// lived in TokenService's file, and governance called it to write the
	// marker that forces a reviewed user to re-authenticate -- to a key whose
	// only reader was TokenService itself. internal/revocation now holds one
	// definition of that marker, and the enforcement point reads what
	// governance writes.

	// ---- governance --------------------------------------------------------
	//
	// governance.RequestService and governance.PolicyEvaluator have left this
	// register the way an entry is supposed to: deleted. The first was 676
	// lines of second access-request workflow whose escalation sweep could
	// never match a row, plus request_approval_chains, the table only it wrote
	// (migration v182 drops it). The second was the third OPA evaluator in the
	// tree. JITService followed once the five live paths that read or revoked
	// jit_grants -- the kill switch, the lifecycle sweep, deprovisioning, User
	// Access 360 and the portal dashboard -- were pointed at the elevations the
	// product actually grants (internal/jitgrant, migration v183).

	// ---- risk --------------------------------------------------------------

	"internal/risk.AlertManager": "security alert generation, deduplication, severity routing and delivery to a security-team mailing list, over its own AlertConfig. A SECOND IMPLEMENTATION -- and this entry previously said something stronger and wrong, that a high-risk login is scored, recorded and nobody told. It is not: risk.Service.RunAnomalyCheck is wired into the identity service through an adapter in cmd/identity-service/main.go, it runs the impossible-travel, brute-force and blocked-IP detectors on a login attempt, and its own CreateSecurityAlert writes security_alerts -- the table the console's Security Alerts page and the admin dashboard's count both read. What AlertManager adds over that is delivery: dedup, severity routing and an email to a security team. Nothing in the product sends one. So the verdict is: delete it, or lift its delivery half onto risk.Service, but the detection and the record are already there. One loose end it leaves behind: alerts carry a remediation_actions array (\"block_request\", \"notify_admin\") that is persisted, displayed nowhere and acted on by nothing.",

	"internal/risk.BehaviorTracker": "behavioural baselines -- typical hours, locations, devices and resources per principal, with MaxDevices/MaxResources thresholds. internal/admin/continuous_auth.go computes a behavioural-anomaly factor of its own. A SECOND IMPLEMENTATION, and the richer of the two: decide which one is the product's, and delete the other.",

	"internal/risk.DeviceFingerprinter": "device fingerprint capture and matching (canvas, WebGL, optional audio) with a fingerprint store. The live device signal is the posture agent plus device_trust. Unreachable, and its config comments describe browser-side collection nothing in web/admin-console performs. Delete unless the browser half is planned.",

	"internal/risk.RiskAssessment": "the result type the three services above return. Dead with them; it will leave this register when they do.",

	// ---- metrics -----------------------------------------------------------

	// The live metrics path is the package-level Prometheus collectors in
	// prometheus.go plus metrics.Handler(), which every service mounts at
	// /metrics. These five Collector types are a second layer that would query
	// the database for business metrics -- and none is registered, so none of
	// those metrics has ever been exported.
	"internal/metrics.OAuthMetricsCollector":      "business metrics for OAuth (token issuance by grant, active clients, consent rates) read from the database. Never registered with the Prometheus registry metrics.Handler() serves, so none of it is exported. Register it or delete it; a dashboard built against these names would be empty.",
	"internal/metrics.AdminMetricsCollector":      "the same, for admin activity: actions per administrator, delegation use, bulk-operation volume. Never registered either, so nothing is exported. Register it or delete it.",
	"internal/metrics.AuditMetricsCollector":      "the same, for audit volume and outcomes by category. Never registered either, so nothing is exported. Register it or delete it.",
	"internal/metrics.GovernanceMetricsCollector": "the same, for access requests, approvals and review campaigns. Never registered either, so nothing is exported. Register it or delete it.",
	"internal/metrics.IdentityMetricsCollector":   "the same, for users, groups and MFA enrolment rates. Never registered either, so nothing is exported. Register it or delete it.",
	"internal/metrics.TracedRedisClient":          "an OpenTelemetry-instrumented wrapper over *redis.Client, mirroring the whole command surface so a caller can swap it in. Nobody did: every service holds the bare client. AN ABSTRACTION NOBODY ADOPTED. Adopt it in one service or delete it -- 21 wrapper methods are 21 chances to drift from the client they wrap.",

	// ---- health ------------------------------------------------------------

	"internal/health.EnhancedHealthService": "a richer health service -- dependency checks plus certificate expiry, build info and uptime. internal/health.HealthService (7 of 7 methods reachable) is the one the services mount. A SECOND IMPLEMENTATION in the same package as the first, which is how it stayed invisible. Fold the certificate-expiry check into the live one and delete the rest.",
	"internal/health.StaticChecker":         "a fixed-answer HealthChecker for tests and placeholders, unreachable. Delete with EnhancedHealthService.",
	"internal/health.FuncChecker":           "a HealthChecker built from a closure, for a caller that wants an ad-hoc check. Unreachable with internal/health.EnhancedHealthService, the only thing that would have taken one. Delete with it.",
	"internal/common/health.HealthService":  "a THIRD health service, in a different package from the other two, with its own HealthChecker interface. Nothing imports it. Delete.",

	// ---- common infrastructure ---------------------------------------------

	"internal/common/cache.Cache":          "a Redis cache layer with TTL policy, key prefixing, retries and optional metrics. No service constructs it. AN ABSTRACTION NOBODY ADOPTED: the services that cache do it against the bare Redis client. Delete, or adopt it somewhere before it is read as the house pattern.",
	"internal/common/cache.ResponseCache":  "HTTP response caching middleware over the above, with an in-memory tier. Unreachable with it.",
	"internal/common/cache.CacheWriter":    "the gin ResponseWriter wrapper internal/common/cache.ResponseCache installs to capture a response body for caching. Unreachable with the cache nobody adopted; delete with it.",
	"internal/common/cache.responseWriter": "the second, unexported ResponseWriter wrapper in internal/common/cache/response.go, doing the same capture as CacheWriter. Unreachable with the cache nobody adopted; delete both with it.",

	"internal/common/middleware.Registry": "a registry that would let middleware be declared with conditions and route-group scoping and composed in a declared order. Every service builds its chain by hand in cmd/*/main.go. AN ABSTRACTION NOBODY ADOPTED. Delete.",
	"internal/common/middleware.Builder":  "the fluent builder that would assemble a chain out of internal/common/middleware.Registry. Unreachable with the registry nobody adopted; delete with it.",

	"internal/common/logger.AuditLogger":       "a structured audit-log helper over zap, unrelated to internal/audit. Nothing constructs it; the services write audit rows through internal/audit. Delete.",
	"internal/common/logger.PerformanceLogger": "request-timing helpers over zap; the services use middleware and Prometheus instead. Delete.",

	// ---- gateway -----------------------------------------------------------

	"internal/gateway/middleware.JWTAuthMiddleware":   "JWKS-backed JWT validation with a key cache, for the gateway. cmd/gateway-service wires its auth elsewhere. Unreachable, so the gateway's own auth middleware has never run: check which path actually guards the gateway before deleting this one.",
	"internal/gateway/middleware.RateLimitMiddleware": "sliding-window rate limiting in Redis, for the gateway. Same shape as above: the live limiter is internal/common/middleware/ratelimit.go. A SECOND IMPLEMENTATION; delete.",
	"internal/gateway/middleware.contextLogger":       "the per-request logger the gateway's logging middleware would attach. Dead alongside internal/gateway/service.go's empty logInfo/logError bodies, which the readiness guide already lists for deletion.",

	// ---- backup ------------------------------------------------------------

	"internal/backup.LocalStorage": "the filesystem implementation of the backup Storage interface. cmd/backup takes a StorageDir and writes to it directly, so this and the interface are unused. AN ABSTRACTION NOBODY ADOPTED: adopt it in cmd/backup (which is where an S3 destination would have to plug in anyway) or delete the interface and both implementations.",
	"internal/backup.Progress":     "the progress reporter internal/backup.LocalStorage and S3Storage would emit while copying. Unreachable with them, because cmd/backup does not use the Storage interface at all. Delete with it.",
	"internal/backup.dirEntry":     "a fs.DirEntry shim internal/backup.LocalStorage.List builds while walking the backup directory. Unreachable with LocalStorage; delete with it.",
	"internal/backup.fileInfo":     "the fs.FileInfo half of the same shim in internal/backup/storage.go. Unreachable with internal/backup.LocalStorage; delete with it.",

	// ---- identity / access -------------------------------------------------

	"internal/identity.filterParser":     "the recursive-descent SCIM filter parser behind identity.ParseFilter, which internal/identity/scim.go calls -- and those handlers are unreachable too. The product's SCIM is internal/provisioning, with its own parseSCIMFilter over an allow-list of attributes. A SECOND IMPLEMENTATION, and the one without the allow-list. Delete identity's SCIM surface with it.",
	"internal/identity.sqlFilterBuilder": "the SQL renderer for identity.filterParser: it turns a parsed SCIM filter into a WHERE clause. Unreachable with the parser and with identity's whole SCIM surface; delete with them.",

	"internal/access.UpstreamPool": "the operator's declaration of a route's backend set -- weights, hash key, active health checks -- and the pure functions that render it for the data plane. tools/tablewriters already carries the other half of this finding: upstream_pools and upstream_pool_members are read by the reconciler and written by nothing, because no handler, route or console page can create a pool. Same verdict, same fix: build the CRUD surface or delete both halves.",
}
