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

	// Six entries left here at once, all deleted.
	//
	// Five business-metric Collectors -- OAuth, admin, audit, governance,
	// identity -- would have queried the database for token issuance by grant,
	// actions per administrator, audit volume by category, access-request
	// counts and MFA enrolment rates, and not one was ever registered with the
	// Prometheus registry metrics.Handler() serves. None of it was exported.
	//
	// Registering them was the other option and it is the wrong one. Each
	// collector runs aggregate queries on every scrape, so adopting them makes
	// scrape-time database load a decision nobody took -- and a Prometheus
	// collector whose query fails exports a zero, which is precisely the defect
	// this branch spent a commit removing from 157 aggregates. A dashboard
	// built on a silently-zeroed count is worse than no dashboard. The live
	// path stays what it is: package-level counters incremented where the thing
	// actually happens.
	//
	// TracedRedisClient went with them: an OpenTelemetry wrapper mirroring the
	// whole redis command surface so a caller could swap it in. Nobody did --
	// every service holds the bare client -- and 21 wrapper methods are 21
	// chances to drift from what they wrap.

	// ---- health ------------------------------------------------------------

	// internal/health.EnhancedHealthService is gone, and its entry was carried
	// out the way the register intends: the verdict said "fold the
	// certificate-expiry check into the live one and delete the rest", so
	// health.CertChecker exists, every service that serves TLS from a file
	// mounts it through RegisterCertCheck, and the second service -- its own
	// Check, its own three handlers, its own RegisterStandardRoutes, all
	// constructed by nothing -- is deleted.
	//
	// StaticChecker and FuncChecker went with it: a checker returning a
	// constant and a checker built from a closure, for the ad-hoc caller that
	// never arrived. A health endpoint reporting what it was told rather than
	// what it measured is the shape this branch keeps removing.

	// ---- common infrastructure ---------------------------------------------

	// internal/common/cache is gone, all four types with it: a Redis cache
	// layer, the response-caching middleware over it and two ResponseWriter
	// wrappers doing the same capture. No service ever constructed any of it.
	//
	// It was load-bearing in one place, in the way an abstraction nobody
	// adopted usually is. cache.ErrRedisUnavailable was the sentinel
	// internal/oauth's isDependencyUnavailable tested first, to turn a Redis
	// brownout on the issue path into a retryable 503 instead of a 500 -- and
	// the only code that could produce it was the cache nobody constructed, so
	// the branch had never fired and its test built the error by hand. The
	// classifier now tests redis.ErrClosed and redis.ErrPoolTimeout, which the
	// client the services actually hold does return.

	// internal/common/middleware.Registry and its fluent Builder are gone: a
	// middleware registry with conditions and route-group scoping, composed in
	// a declared order, that every service ignored in favour of building its
	// chain by hand in cmd/*/main.go.
	//
	// internal/common/logger.AuditLogger and PerformanceLogger went with them.
	// The first was a structured audit-log helper unrelated to internal/audit,
	// which is where audit rows are actually written; the second was
	// request-timing helpers the services do with middleware and Prometheus.

	// ---- gateway -----------------------------------------------------------

	// The three gateway entries are gone, and the middle one was not dead code.
	//
	// JWTAuthMiddleware: JWKS-backed JWT validation with a key cache. Its entry
	// asked for the check before deleting -- which path actually guards the
	// gateway -- and the answer is in internal/gateway/routes/admin.go: every
	// group is `router.Any("/*path", proxyRequest(proxy))` and the comment says
	// "the backend owns auth and routing; the gateway stays a thin
	// pass-through". Each backend authenticates its own requests. So this was
	// redundant rather than missing, and deleting it removes the second place a
	// reader could think the gateway authenticates.
	//
	// RateLimitMiddleware: THIS ONE WAS A GAP. gateway.Config has carried
	// EnableRateLimit (default true) and a RateLimitConfig of 100/min with
	// 20/min for auth paths since it was written, read from ENABLE_RATE_LIMIT
	// and rate_limit.*, passed into the config in cmd/gateway-service -- and
	// consumed by nothing, because this middleware was its only reader and no
	// binary constructed it. The service facing the internet answered an
	// unlimited number of requests while its configuration said 100 a minute.
	// cmd/gateway-service now mounts middleware.DistributedRateLimit, the
	// limiter the other five services use, on the same config values.
	//
	// contextLogger: the wrapper WithLogger returned, stamping correlation id
	// and path on each line. Nothing called WithLogger. Its entry blamed
	// service.go's empty logInfo/logError bodies, which this branch has since
	// filled, so what was left was one unused wrapper.

	// ---- backup ------------------------------------------------------------

	"internal/backup.LocalStorage": "the filesystem implementation of the backup Storage interface. cmd/backup takes a StorageDir and writes to it directly, so this and the interface are unused. AN ABSTRACTION NOBODY ADOPTED: adopt it in cmd/backup (which is where an S3 destination would have to plug in anyway) or delete the interface and both implementations.",
	"internal/backup.Progress":     "the progress reporter internal/backup.LocalStorage and S3Storage would emit while copying. Unreachable with them, because cmd/backup does not use the Storage interface at all. Delete with it.",
	"internal/backup.dirEntry":     "a fs.DirEntry shim internal/backup.LocalStorage.List builds while walking the backup directory. Unreachable with LocalStorage; delete with it.",
	"internal/backup.fileInfo":     "the fs.FileInfo half of the same shim in internal/backup/storage.go. Unreachable with internal/backup.LocalStorage; delete with it.",

	// ---- identity / access -------------------------------------------------

	"internal/access.UpstreamPool": "the operator's declaration of a route's backend set -- weights, hash key, active health checks -- and the pure functions that render it for the data plane. tools/tablewriters already carries the other half of this finding: upstream_pools and upstream_pool_members are read by the reconciler and written by nothing, because no handler, route or console page can create a pool. Same verdict, same fix: build the CRUD surface or delete both halves.",
}
