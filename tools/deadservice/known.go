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

	// internal/audit.AnomalyDetector is gone: brute-force and suspicious-pattern
	// detection over audit events, with per-principal failed-login trackers and
	// a DetectorConfig of thresholds, constructed by nothing. The live risk
	// signals are elsewhere and unrelated -- internal/admin/continuous_auth.go
	// scores IP change, device and behaviour, and internal/risk scores logins --
	// so this was a second implementation minus the audit-event corpus it would
	// have read.

	// ---- risk ---------------------------------------------------------------
	//
	// All four risk entries are gone.
	//
	// AlertManager: alert dedup, severity routing and delivery to a security
	// mailing list. The detection and the record were never the gap --
	// risk.Service.RunAnomalyCheck is wired into the identity service, runs the
	// impossible-travel, brute-force and blocked-IP detectors on a login, and
	// writes security_alerts, the table the console's Security Alerts page and
	// the admin dashboard count both read. What AlertManager added was delivery,
	// and nothing in the product sends one. Still open, and recorded here rather
	// than lost with the type: an alert carries a remediation_actions array
	// ("block_request", "notify_admin") that is persisted, displayed nowhere and
	// acted on by nothing.
	//
	// BehaviorTracker: per-principal baselines of typical hours, locations,
	// devices and resources. internal/admin/continuous_auth.go computes a
	// behavioural-anomaly factor of its own, and that one runs. Its
	// haversineDistance went to geo.go, because the impossible-travel detector
	// and two live signals measure with it.
	//
	// DeviceFingerprinter: canvas/WebGL/audio fingerprint capture with a
	// fingerprint store, whose configuration comments describe browser-side
	// collection no console page performs. The live device signal is the posture
	// agent and device_trust. TrustLevel and IsPrivateIP came out with it, into
	// trust_level.go and ip.go, because the risk scorer uses both.
	//
	// RiskAssessment stays -- CalculateRiskScore returns it and the service acts
	// on its Score and Recommendation. What left the register with it were its
	// three methods, GetSignalSummary, ToJSON and GetHighRiskSignals: a
	// reporting surface no caller anywhere used, whose only exercise was three
	// tests written against it.

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

	// The four backup entries are gone, and one of them was holding up a false
	// claim in a document an operator reads during a disaster.
	//
	// LocalStorage implemented a Storage interface with no reference outside
	// its own declaration, and docs/PRODUCTION-READINESS.md said Manager
	// "routes through the Storage interface; both LocalStorage and S3Storage
	// are wired". Manager does not: local backups are plain os.ReadFile /
	// os.WriteFile against config.StorageDir, and S3 is reached through the
	// concrete *S3Storage. The capability was real -- a created backup is
	// uploaded, and a restore falls back to the bucket -- so the document is
	// corrected rather than the code bent to match. Progress, its Reader, the
	// DirEntry/FileInfo shims and the whole os-function indirection layer the
	// tests substituted went with it: every one of them existed so LocalStorage
	// could walk a directory.

	// ---- identity / access -------------------------------------------------

	// internal/access.UpstreamPool was the last entry, and the register is now
	// empty.
	//
	// Its verdict was "build the CRUD surface or delete both halves", and the
	// surface is built: /api/v1/upstream-pools with its members, the route link
	// on proxy_routes, and a console page. Two things came out of doing it that
	// the entry had not seen.
	//
	// THE RENDERER WAS NEVER CALLED. The entry described two halves -- a schema
	// and renderer that worked, and no way to create a pool. There was a third.
	// APISIXReconciler.Reconcile loaded the BrowZer routes and nothing else, so
	// BuildEdgeRoutesForPools -- correct, tested, exported -- had no caller. A
	// pool created by hand and linked by hand would still never have reached
	// APISIX. Reconcile converges both sets now, and prunes only the generated
	// prefixes it was able to read this pass, so a failed pool read leaves the
	// edge alone instead of emptying it.
	//
	// A POOL CAN BE CONFIGURED AND NOT IN EFFECT, which is the shape this branch
	// keeps finding. BuildUpstream refuses to render a pool with no usable
	// member, because an upstream with no node black-holes the route; the route
	// falls back to its single to_url. Right at runtime, and silent: an operator
	// draining the last member for maintenance would be told "member removed"
	// while traffic kept flowing. Every response describing a pool now carries
	// in_effect and the reason, and deleting a pool routes still name is refused
	// rather than quietly reverting them.
}
