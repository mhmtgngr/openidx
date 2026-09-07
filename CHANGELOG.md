# Changelog

All notable changes to OpenIDX are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **A disabled user's access token kept working for an hour
  (`internal/revocation.RevokeUserTokens`, wired into every sever path).**
  Writing J7's missing integration case — "disable or kill-switch a user and
  everything is severed" — found the journey's third half broken. Identity's and
  provisioning's `deprovisionUser` and the access-service kill switch each
  collected the user's live session ids and published `revoked_session:<id>`,
  which the **refresh grant** honours. Nothing they wrote is read by
  `/oauth/userinfo` or `/oauth/introspect`: those consult the per-user revocation
  cutoff and the per-token blacklist and nothing else, and no sever path wrote
  the cutoff. So an administrator disabling a leaver, or firing the kill switch
  on a compromised account, cut new logins and cut the refresh — and the access
  token already in that browser answered for the rest of its hour and
  introspected `active: true`, while the console showed the account disabled.

  That put the controls in the wrong order. An access-review revocation, the
  slowest and least urgent control in the product, already wrote the cutoff
  (that half was fixed when `internal/revocation` was created); the kill switch,
  the one you reach for when an account is compromised, did not. All three sever
  paths now call `revocation.RevokeUserTokens`, which lives in the package that
  owns the key so a fourth spelling cannot appear. The kill switch reports it as
  `iam_access_tokens_revoked` rather than swallowing a failure, because "the
  tokens were not actually cut" is something an operator needs in the record.

  `test/integration/leaver_test.go` drives all three halves against the running
  services and asserts them separately: a test that checked only the login and
  the refresh would have passed for the whole time this was broken, which is how
  it stayed broken.

### Added

- **Upstream pools reach the operator, and the data plane
  (`/api/v1/access/upstream-pools`, `internal/access/upstream_pools_handlers.go`,
  Upstream Pools console page).** Migration v130 built the place to declare a
  route's backend set — algorithm, hash key, per-node weights, active health
  checking — and `internal/access/upstream_pools.go` renders it into the APISIX
  upstream object. Neither half could be used: no handler, route or console page
  could create a pool, so `upstream_pools` was empty on every install. Building
  the missing half turned up a third gap neither register had recorded:
  `BuildEdgeRoutesForPools`, the only function that renders a pool-backed route
  for the data plane, was **called by nothing**. `APISIXReconciler.Reconcile`
  loaded the BrowZer routes and stopped there, so a pool inserted by hand and
  linked by hand would still never have reached APISIX. The reconciler now
  converges both sets in one pass and prunes only the generated prefixes it was
  able to read, so a failed pool read leaves the edge alone instead of emptying
  it. `proxy_routes.upstream_pool_id` is settable from the route API and the
  pool it names is resolved inside the caller's organization first — the foreign
  key alone would have accepted another tenant's pool and sent this route's
  traffic to their backends.

  Two behaviours here are not CRUD, and they are why this was built rather than
  deleted. **A pool can be configured and not be in effect:** `BuildUpstream`
  refuses to render a pool with no usable member, because an upstream with no
  node black-holes the route, so the route falls back to the single address in
  `to_url`. Right at runtime and, until now, silent — an operator draining the
  last backend for maintenance would be told "member removed" while traffic kept
  flowing. Every response describing a pool carries `in_effect` and the reason,
  and the page leads with it. **Deleting a pool moves traffic:** the foreign key
  is `ON DELETE SET NULL`, so a delete would quietly revert every route on the
  pool to one backend with no health checking. It is refused while any route
  still names the pool, and the refusal lists them.

  This empties the dead-service register (`tools/deadservice`) — `UpstreamPool`
  was its last entry — and takes both `upstream_pools` and
  `upstream_pool_members` off the unwritten-table register.

- **The tamper-evident audit log, made real (migration v181,
  `internal/audit/chain.go`).** The docs index, the architecture page, the audit
  reference page and the README's readiness checklist all state that OpenIDX
  keeps a tamper-evident HMAC hash-chain audit log. `internal/audit/logger.go`
  has carried the primitives from the beginning — HMAC-SHA256 over a canonical
  form, a previous-hash link, a chain walk that names the first break — and no
  binary has ever reached them; no migration created a column to store a hash
  in; and the tests covering the chain declared their own `ComputeHashForChain`
  method inside the test file to make the assertions work. Four published claims
  rested on code that has never run. Now: v181 adds `chain_seq`, `prev_hash` and
  `event_hash` with a unique `(org_id, chain_seq)` index, a background sealer
  chains each organization's events under a per-org advisory lock, and
  `GET /api/v1/audit/chain/verify` answers whether that tenant's trail is
  intact — naming the event where it broke. The chain is **per tenant**, because
  `audit_events` is under FORCE RLS and an install-wide chain would be
  unverifiable by the tenant whose rows it covers. It is sealed by a sweep
  rather than on insert, because sixteen statements across the tree insert into
  that table and a per-org lock at each would put a serialization point in the
  middle of login; the cost is reported rather than hidden — verification
  returns the unsealed count, so the sweep's lag is visible in the evidence.
  `AUDIT_CHAIN_SECRET` is generated by `scripts/generate-secrets.sh`, separate
  from every other secret on purpose (whoever can write the audit database must
  not hold the key to re-seal a doctored trail), and `ValidateProduction`
  refuses a production start without it. Detects an edit to any sealed row, a
  deleted sealed row, and a row backdated into a sealed run; a table-driven test
  rewrites **each** of the fourteen stored columns in turn and requires every
  one to break the chain, because a hash covering most of a row is worse than
  none — verification would pass and vouch for the edit.

- **`tools/deadservice` — a gate for whole services no binary can reach.**
  `internal/governance/request.go` is 676 lines of access-request workflow:
  submit, approve, deny, cancel, manager resolution, notification hooks, and an
  escalation sweep that finds every request past its approval SLA and adds the
  escalation approvers. It has tests. It is the only code that writes
  `request_approval_chains`, a table migration v58 created for it and v64 put
  under the RLS belt. `NewRequestService` is called nowhere: the live workflow
  is a different implementation in `workflows.go`, which never writes that
  table, so the sweep's `INNER JOIN` matches zero rows on every install and
  would keep matching zero even if the checker were started. Nothing in the
  repository could see this — it compiles, its SQL is valid and carries its
  tenant predicate, its tests are real tests exercising real code, and
  `tablewriters` counts its `INSERT` as a writer because a census of SQL
  literals cannot tell a statement that runs from one that cannot. An earlier
  fix on this branch spent its effort on a bug inside that sweep. The gate is
  Rapid Type Analysis from every binary's `main`; a finding is a type whose
  constructor is unreachable and not one of whose methods any binary reaches,
  which is the shape that misleads rather than every unused helper. The register
  opened at **41**, with a verdict apiece saying whether the answer is to wire
  it or delete it, and it shrinks. The largest entry is its own task: the
  tamper-evident HMAC hash-chain audit log advertised on the docs index, the
  architecture page, the audit reference and the README's readiness checklist is
  implemented in `internal/audit/logger.go`, reachable from nothing, and no
  migration creates a column to store a chain in.

- **`tools/zeroanswer` — a gate for the defect class behind the three entries
  below.** A one-row aggregate (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, `EXISTS`)
  always returns exactly one row, so a discarded `Scan` error there can never
  mean "there is no data" — it means the query did not run, and the destination
  keeps its zero, which the caller then prints on a dashboard, writes into a
  compliance report, or reads as a control that passed. Nothing else in the
  repository can see this: the SQL is valid so `sqlprepare` plans it, the tenant
  predicate is present so `orgscope` passes it, the handler answers 200 with a
  well-formed body so the contract test passes it, and `COUNT` over no rows is
  also 0. Only the error told the two apart. The register (`known.go`) opened at
  83 with a verdict per site saying what the zero does, and shrinks; a new
  finding fails the build, and so does an entry that no longer reproduces.

### Fixed

- **An invitation token was never spent (`handleAcceptInvitation`).** Accepting
  an invitation read the row `WHERE status = 'pending'`, created the account,
  and forty lines later ran `UPDATE user_invitations SET status = 'accepted'`
  with the error discarded. If that write failed the invitation stayed pending
  and the token stayed usable — a single-use credential that could create a
  second account, and a third. Even checked, `SELECT`-then-`UPDATE` is a
  check-then-act: two requests arriving together both pass the read before
  either writes. One `UPDATE … RETURNING` now reads and burns at once, so
  exactly one caller can claim a token, and a failure anywhere after it puts
  the invitation back rather than costing the invitee their invitation over a
  taken username. The same handler also skipped the password write entirely
  when hashing failed (`if err == nil`) and discarded the role and group
  inserts, so it could answer **201 "Account created successfully"** for an
  account with no password and none of the access the invitation promised;
  those three now share a transaction and the response says plainly when it
  could not be finished.
- **No way to run the guards CI runs (`make guards`).** There are 29 shell
  guards under `scripts/` with 27 self-tests, invoked from several different CI
  jobs with different flags, and nothing ran them as a set — so "I ran the
  guards" meant "I ran the ones I remembered", and the rest were found by CI
  twenty minutes later. That happened on this branch: a database-gated test
  helper that read only a private environment variable, and so would have
  skipped on every CI run, went in because `check-test-reachability.sh` was not
  among the five run by hand beforehand. `scripts/run-ci-guards.sh` reads the
  invocation list out of `.github/workflows` rather than keeping a copy of it,
  because a hand-kept list drifts from CI exactly the way the unit-test matrix
  drifted from the tree — and a runner that omits a guard CI runs is worse than
  none, since it reports that the guards passed. It runs all 54 in about 40
  seconds, treats an invocation CI writes with `|| true` as informational, and
  reports the one whose argument CI computes as **not run** rather than as a
  pass. Six cases of its own keep it honest, chief among them that finding no
  guards is an error and not an empty success.
- **Six Ziti handlers answered success over a record they had not changed, and
  a SCIM mirror the provider reads back.** Each of these makes the controller
  call first, checks it, and returns on failure — then wrote the database mirror
  with the error discarded. So `DELETE /ziti/services/:id` answered *"ziti
  service deleted"* while the row and its BrowZer route survived; the identity
  delete did the same; `PUT` on a service policy answered 200 with the new
  service and identity roles while the console kept showing the old ones for a
  policy the network was already enforcing differently; and the identity
  attribute patch — the attributes overlay policies match on — did likewise.
  All six now report the divergence and say which way round it is: the network
  changed, the record did not, and here is what will look wrong until it does.
  In the same file, `handleGetEnrollmentJWT`'s write is genuinely best-effort —
  a cache of a token the controller had just returned — and now carries a
  `//silentwrite:ok` saying so, which is the distinction the gate exists to make
  visible.
  `UpdateSCIMUser` had the same split: the `users` row was checked, its
  `scim_users` representation was not. That representation is what a SCIM `GET`
  answers with, so a failure left the identity provider reading back the values
  it had just replaced — and a provider that reconciles against what it reads
  either sends the change for ever or concludes it never applied. The two are
  one transaction now.
- **A refused remote-support session was not ended
  (`HandleAgentConsent`).** The denial branch carries the comment *"A denial
  ends the session immediately (fail-closed)"*, and the statement under it
  discarded its error. On a failure the session was **not** ended, the audit
  still recorded `remote_support.consent_denied` with outcome `success`, and
  the agent was answered `{"consent_status":"denied","status":"ended"}` — so
  the person at the device refused to have their screen watched, was shown a
  confirmation, and the session stayed live, with every record saying they had
  been listened to. Both consent branches now check the write and the row count,
  audit the failure as a failure, and tell the agent the refusal could not be
  recorded and the session may still be active.
- **A device the console called trusted could be untrusted (`trustDevice`).**
  The function ran two statements: a nudge marking the user's Ziti identity
  attributes stale, whose error was checked and logged, and the `UPDATE` that
  actually sets `known_devices.trusted`, whose error was discarded. The
  belt-and-braces statement was the checked one. An administrator could approve
  a trust request, the request row would say approved, the user would be
  notified — and the posture gate would go on refusing the device for a reason
  visible nowhere. It now reports both a failed write and a row count of zero,
  and both callers pass that up instead of announcing an approval the device
  never received.
- **A directory sync could report success over a group it did not sync
  (`internal/directory`).** Both the LDAP and the Entra ID membership passes
  ran, per group, a `DELETE` of the directory-managed rows followed by an
  `INSERT` per current member — both errors discarded, and no transaction round
  the pair. The dangerous ordering is the `DELETE` failing while the `INSERT`s
  succeed: a membership the directory **removed** survives, and `RunSync` goes
  on to write `sync_status = 'synced'`. That is deprovisioning that did not
  happen, on the schedule an operator relies on to take access away when
  somebody leaves a team, with the console saying the sync worked. The reverse
  order silently drops access the directory still grants, and between the two
  statements the group is briefly empty, so a membership check landing there is
  answered no for a user who has the access. One transaction now moves the old
  rows and the new ones together, and the sync reports which groups kept the
  membership they had.
- **An approval chain could come out shorter than its policy
  (`createApprovalRows`).** Five `INSERT`s into `access_request_approvals`, one
  per approval-step type, every one discarding its error. Losing the whole
  chain is visible — nobody can approve the request. Losing *part* of it is
  silent and worse: `handleApproveRequest` fulfils a request when the count of
  pending approvals reaches zero, so a two-step policy that produced only its
  first row is granted by one approver with the second step skipped, and the
  audit trail says it was approved. The builder reports failure now, and the
  handler withdraws the request rather than leaving a half-routed one standing.
- **The writes whose failure nobody learns about (`tools/silentwrite`, new
  gate).** 137 statements across the tree change the database through
  `_, _ = …Exec(…)` or a bare call, and cannot tell whether they did. Many are
  best-effort by design — a last-seen timestamp, a queue counter, a telemetry
  row — and wrapping those in error paths nobody reads would be worse code. But
  "best-effort" is a judgement the tree records nowhere: `_, _ =` is Go's
  spelling for "I meant to drop this", equally true of the timestamp and of the
  revoked credential. The gate reports each one and is cleared either by
  handling the error or by a `//silentwrite:ok` reason above the call saying
  what is lost — the `//orgscope:ignore` convention this repository already
  uses. The fixes above take the count to 113, one site carries a reason, and
  the gate holds it there: it can only go down.
- **115 log fields carried a request value nothing cleaned
  (`internal/common/logsafe`, new guard).** CodeQL filed two "Log entries
  created from user input" alerts against `internal/admin/attestation.go`.
  Reading the file showed the shape plainly: two fields there already went
  through `logsafe`, and three more logged a campaign id taken straight from
  `c.Param("id")`. The earlier sweep had fixed the sites CodeQL named rather
  than the class behind them, so an AST census over the tree — function-scoped,
  because two handlers in one file routinely both call something `id` or
  `token` — found 115 of them across 24 files: agent ids, session ids, SAML
  provider ids, group and role ids, an OAuth redirect URI, a social-login
  provider's `error_description`. All now go through `logsafe.String`.
  This is not a log-forging fix: `encoder_test.go` already established that
  both zap encoders escape a field, and the guard against forging a line is
  `no_interpolated_message_test.go`. It is a fix for the other three reasons
  the package exists — nothing bounded the length, so a megabyte of `id` in
  every warning fills a disk and buries the entry that mattered; the escaping
  belongs to the encoder and does not survive the hop to Elasticsearch and on
  to a SIEM; and it is the shape a static analyser will keep reporting until
  the class is closed. `TestNoRequestValueReachesALogFieldUnwashed` now fails
  the build on the next one, and eight cases built from synthetic source keep
  the guard itself honest in both directions.
- **The dead-service gate brought a vulnerable dependency in with it
  (`golang.org/x/mod`).** Promoting `golang.org/x/tools` to a direct dependency
  so `tools/deadservice` could do reachability analysis also recorded
  `golang.org/x/mod v0.38.0` in `go.mod`, and that version carries
  CVE-2026-56864 and CVE-2026-56865 — a malicious `GOSUMDB` serving arbitrary
  module content, and a transparency-log tile verification bypass. `govulncheck`
  stayed green (nothing reaches `sumdb/tlog` from any binary here) while the
  filesystem scan went red, which is the difference between the two tools rather
  than a disagreement. Bumped to v0.40.0, pulling `x/tools` to v0.49.0 and
  `x/net` to v0.58.0 with it. `go mod tidy` then dropped
  `github.com/open-policy-agent/opa` and eight of its transitive dependencies:
  the embedded OPA engine's only importer in the tree was
  `internal/governance/policy.go`, the third policy evaluator deleted earlier on
  this branch, so the requirement had been holding a compiled-in Rego runtime
  the product never called. Policy decisions go to the OPA **server** over HTTP,
  as they always did.
- **`cmd/` had no unit-test job, and one package's tests had never run at all
  (`tools/testmatrix`, new gate).** The unit-test matrix in CI was a
  hand-written list of `internal/*` and `pkg/`. It did not name `cmd/`, so the
  ten service main packages had no per-package job — which is how the seven red
  production-config tests below went unremarked across several pushes. They were
  never unverified (`go test -race ./...` covers the module), but that signal
  arrives twenty minutes in under a check named "Race Detector", and a red tick
  with that name reads as a concurrency problem rather than as a broken
  production gate in seven services. The matrix now names every package, in
  `package`/`paths` pairs so several small directories can share a runner, and
  `tools/testmatrix` fails the build when a directory holding `_test.go` files
  is named by neither the matrix nor a register entry citing the job that does
  run it — the same inversion applied to `tools/orgscope`, for the same reason:
  a hand-maintained allow-list cannot notice what is missing from it.
  The gate also refuses coverage that compiles nothing, which turned up
  `cmd/rekey`: its single test file is behind `//go:build integration`, so
  although the package sits under `./cmd/...` every job compiled zero tests out
  of it. Two tests — a 294-line end-to-end proof that rotating the key-encryption
  key re-seals every stored secret under the new key and leaves the plaintext
  readable, the tool an operator reaches for after a key compromise — had never
  executed anywhere. They pass; the Integration Tests job now names
  `./cmd/rekey/...` so they keep doing so.
- **Seven production-config gate tests went stale when the audit chain became
  required (`cmd/*/main_test.go`).** `AUDIT_CHAIN_SECRET` joined the
  `ValidateProduction` critical list in the audit hash-chain change above. The
  config package's own tests were updated; the seven `cmd/*` copies of "a valid
  production config" were not, so each service's only automated proof that a
  production start is accepted began failing. They run in CI — but only inside
  `go test -race ./...`, since the per-package unit matrix does not list `cmd/`
  at all, so a self-inflicted red would have arrived twenty minutes late under a
  job named "Race Detector".

- **An access review's revocation wrote a key nothing read
  (`internal/revocation`).** When a reviewer revokes somebody's access in a
  certification campaign, governance calls `killUserSessions` to set *"the
  user-wide token-revocation marker the auth middleware checks, so a live
  session cannot keep using access an access review just revoked"*. It wrote
  `auth:user_revoked:<uid>` — a key format that came from `internal/auth`'s
  `TokenService`, whose `isUserRevoked` was **its only reader in the entire
  tree**, and which no binary reaches. The enforcement point,
  `internal/oauth`'s `IsAccessTokenRevoked`, reads a different key,
  `oauth:user_tokens_revoked_at:<uid>`. So an access review could revoke
  access, record it and audit it while the user's live session and outstanding
  access tokens kept working until they expired on their own — and the reviewer
  had no way to know, because the write succeeded. Neither half was wrong on its
  own: each was a correct implementation of a contract the other did not share,
  and the piece they shared lived in unreachable code where it looked
  authoritative. `internal/revocation` now holds one definition — the key, the
  value format, the TTL and the `iat <= cutoff` comparison — and both `/oauth/
  logout-all` and the review path go through it. The comparison is `<=`, not
  `<`, so a token minted in the same wall-clock second as the revocation does
  not survive it. Two guards: a test that writes the marker exactly as
  governance writes it and requires `IsAccessTokenRevoked` to see it, and a
  census that fails if any file outside the package spells a revocation key
  itself — restoring the old literal in `killUserSessions` makes it name the
  file and the fragment.

- **The kill switch did not revoke the elevation the product actually grants,
  and reported zero (migration v183, `internal/jitgrant`).** OpenIDX had two
  representations of a just-in-time elevation. The live one is an
  `access_requests` row — `resource_type` role/group/application, status
  `fulfilled`, `expires_at` set — that governance's approval workflow creates
  along with the assignment, and that its expiry sweep ends. The other was the
  `jit_grants` table, written only by `internal/governance/jit.go`, a service no
  binary could reach, so it has been **empty on every install ever run**. Five
  live paths aimed at it. The kill switch — the control an operator presses when
  an account is compromised — revoked `jit_grants` and published
  `pam_jit_grants_revoked`, so it left the user holding every elevated role the
  approval workflow had granted them and answered `0`, which on that response
  reads as *"this user held none"*. The lifecycle sweep's revocation of disabled
  users' elevations and deprovisioning's revocation of a leaver's did nothing at
  all. User Access 360 listed a user's active elevations (always empty) and the
  portal dashboard counted them (always 0), on two pages whose entire job is to
  say what access somebody has. All five now go through the new
  `internal/jitgrant`, which holds one definition of an active elevation and one
  way to end one — the shared revocation used to be unexported inside
  `internal/governance`, which is precisely why the other three packages each
  wrote their own SQL against the wrong table. The tests that "covered" these
  paths seeded `jit_grants` rows by hand, so they proved only that a query could
  find a row invented for it; they now seed a real elevation, and reverting the
  kill-switch fix makes `TestKillSwitch_SeversAllPillars` report
  `JITGrantsRevoked:0` with *"active jit grants remain: 1"*. One gap is recorded
  rather than closed: `handleCreateAccessRequest` accepts any duration
  `parseDuration` takes, so a "time-bound" elevation still has no ceiling.

### Removed

- **A second, unreachable SCIM 2.0 server in `internal/identity` — and the
  documentation that described it instead of the live one.** 6,114 lines across
  eleven files: full Users and Groups handlers, a SCIM schema layer, a
  member-management path, a PATCH path parser with filtered operations, a
  recursive-descent filter parser and a SQL renderer for it, and 2,257 lines of
  tests exercising all of it. `RegisterSCIMRoutes` is exported, complete and
  called by nothing: its single mention anywhere in the tree is its own doc
  comment. The product's SCIM is `internal/provisioning`, mounted by
  `cmd/provisioning-service` at the same `/scim/v2` paths and covering the same
  surface. Removing the eleven files leaves `internal/identity` building and
  vetting unchanged — nothing outside them referenced a single one of their 201
  declarations.
  The cost of the duplicate was paid by the documentation. `docs/SCIM.md`
  advertised seven filter operators (`eq`, `ne`, `co`, `sw`, `ew`, `gt`, `lt`)
  and an example composing two conditions with `and`;
  `docs/SCIM-FEATURES-LOCATION.md` printed two curl commands, one filtering
  `name.givenName sw`, both quoting values with `'`.
  The live parser implements exactly one form —
  `attribute eq "value"`, double-quoted, over a four-attribute allowlist for
  Users and two for Groups — and answers **400 `invalidFilter`** to everything
  else, deliberately, because an IdP treats a filtered lookup as an existence
  check and a silently-ignored filter would return the whole page: the IdP then
  creates a duplicate account or skips a deprovision. So six of the seven
  documented operators, the composition and three of the four printed examples
  failed against the running product. They were written against the richer
  parser — the one no binary reaches. Both documents now describe the live
  behaviour, including what is refused and why, and
  `TestEveryDocumentedSCIMFilterIsOneTheProductAccepts` extracts every
  `?filter=` expression printed in them and drives it through the parser, so a
  filter example that cannot work cannot be published again.
- **`internal/auth`'s `TokenService`, `SessionService` and `RBACMiddleware`.**
  JWT mint/validate/revoke, Redis sessions with a concurrency cap, and gin RBAC
  enforcement — 1,498 lines with four test files, each type constructed **only
  by its own tests**. The live equivalents are `internal/oauth` (tokens,
  sessions, and a per-client concurrent-session policy that is richer than the
  cap here) and each service's own auth middleware. The project readiness guide
  held `token.go`'s configurable fail-closed revocation up as a pattern to copy;
  it survives where it matters — `IsAccessTokenRevoked` returns the error and
  its callers fail closed — so what was deleted is the copy, not the pattern.
  One of these files was load-bearing in the worst way: `UserRevocationKey`
  lived in it, and governance called it, which is the defect above. The
  package's live half (`context.go`, `roles.go` and their tests) is untouched.

- **Two governance services no binary could reach, and the table one of them
  wrote (migration v182).** `internal/governance/request.go` was a 676-line
  second implementation of the access-request workflow — submit, approve, deny,
  cancel, manager resolution, notification hooks and a `StartEscalationChecker`
  that swept every org for requests past their approval SLA. It had tests, and
  two migrations existed for `request_approval_chains`, the table only it wrote.
  `NewRequestService` was called by nothing: the live workflow is
  `workflows.go`, which writes `access_request_approvals` and has never touched
  the chain table, so the escalation sweep's `INNER JOIN` matched zero rows on
  every install and would keep matching zero even if the checker were started.
  It also carried a defect that would have been a P0 the day anyone wired it: a
  failed approval-record `INSERT` was logged and skipped, and completion was
  "no approval row still pending" — so a missing row silently **reduced** the
  approvals a request needed. `internal/governance/policy.go`'s
  `PolicyEvaluator` went with it: the third OPA evaluator in the tree, after
  `internal/common/opa` (which the fail-closed middleware uses) and
  `internal/abac`. `ApprovalStep` and its constants, which the live workflow
  reads out of a policy, survive in `approval_chain.go`.

### Fixed

- **A single logout that did not log anyone out, and a returned credential the
  record still shows as held.** Two more writes whose failure was invisible to
  the caller, both on paths whose whole job is to take access away. The
  IdP-initiated SAML SLO deleted the session row in a bare `Exec` inside an
  `if org, err := ...; err == nil`, then cleared the cookie and rendered *"You
  have been logged out"* regardless of what happened: a cleared cookie is not a
  logout, it only stops **this** browser from presenting the token, so anyone
  else holding it — the shared machine the user just walked away from, a proxy
  log — kept a live session while the user was told the opposite. The delete is
  checked now, the cookie is left alone when it fails (a browser that has
  forgotten a token the server still honours is the same asymmetry, and it costs
  the user the retry), and the confirmation page is not shown. Returning a
  checked-out vault credential revoked the grant (checked) and then marked the
  request expired (`_, _ = ...`), so a failed `UPDATE` left the request reading
  `fulfilled` — still checked out to that user in the console, still counted as
  held by the JIT expiry sweep — under a `200 {"status":"returned"}` and an
  audit event saying `jit_credential.checkout_returned` / `success`. The grant
  really is gone by then, so the answer is a 500 the caller can retry rather
  than a return that did not finish, and the audit event is no longer written
  for one.

- **Offboarding a leaver could leave them everything, and report success.**
  `handleOffboardUser` is five statements — disable the account, revoke the API
  keys, remove the group memberships, remove the role assignments, terminate the
  sessions — and only the first had its error checked. The other four ran as
  bare `Exec` calls with the error discarded, and the handler then answered
  *"User offboarded successfully"*. So a leaver could be disabled while keeping
  every API key, every group, every role and every live session, and the person
  who pressed the button was told the offboarding was complete — which is the
  reason nobody would go back and look. It is one transaction now: a step that
  cannot run changes nothing and answers 500. Three more credentials that could
  not be spent but were accepted anyway: a **magic link**'s `status='used'`
  marker (a failed mark left the emailed sign-in link redeemable again, for as
  long as it had left to live), a **phone-call MFA challenge**'s completion
  marker (same shape, same code re-presentable), and the **access tokens** a
  user's *"revoke this application's access"* was supposed to delete — the
  refresh-token delete beside it was checked, this one was not, so the
  application kept calling the API while the user was told the authorization was
  revoked.

- **A certification decision recorded access as revoked while the access was
  still held.** `handleDecideAttestationItem` marked the item
  `decision='revoked'` with a statement that answers 500 on failure, and *then*
  ran the `DELETE FROM user_roles` / `user_application_assignments` /
  `group_memberships` / `vault_access_grants` that actually removes the access —
  each with its error discarded. So a reviewer clicked **Revoke**, the
  certification recorded the access as removed, the campaign counted the item as
  decided and could auto-complete on it, and the role was still assigned. In an
  identity governance product this is the worst available failure: the evidence
  says the access was removed and it was not. The read that decided *which*
  access to tear down had the same defect — a failed read left the resource type
  empty and every branch fell through, deleting nothing. The decision and the
  revocation now share one transaction, so a revocation that cannot run leaves
  the item pending and answers 500. Seven more writes that silently did not
  happen: a **logout** left both the durable revocation and the Redis marker the
  proxy actually reads (so the session kept working while the person was told
  they had signed out); **continuous verification** could not revoke a session it
  had just denied; the **PAM risk gate** tore down the live connection but could
  not mark the session suspended, so it still read as active on the dashboard;
  the **idle-timeout** revocation; an **AI-agent credential rotation** that
  minted a new key without revoking the old one and reported success; a
  **cancelled agent enrolment** whose token stayed live; and — the sharpest of
  those — the `used_at` marker that *is* the single-use property of an enrolment
  token, so a failed mark left a one-time token redeemable again.

- **A CAEP `account-disabled` event that did not disable the account was
  acknowledged as applied.** `applyCAEPEvent` discarded the error on `UPDATE
  users SET enabled=false` and returned `"applied"` regardless — so a federated
  partner reporting a compromised account got a `202`, the receiver wrote
  `outcome='applied'` to its own record, and the account stayed enabled. RFC
  8935's `202` acknowledges receipt, so the transmitter never re-delivers; the
  dedup row would have discarded the re-delivery in any case. Three more in the
  same eight lines: the **refresh-token revocation**'s error was discarded (a
  refresh token surviving a session revocation is a live credential for the
  account you were just told to shut down), a **missing organization** silently
  skipped the disable and still reported success, and **`resolveUserBySubject`**
  could not tell "this subject is not a user here" from "the lookup did not
  run", reporting both as `ignored`. An event that cannot be applied now answers
  `503` and is *not* recorded as seen, so the transmitter re-delivers. **The
  tests that covered this named a table the product does not have:** the
  fixtures created `refresh_tokens`, the code deletes from
  `oauth_refresh_tokens`, and the discarded error meant both tests passed while
  proving nothing about refresh-token revocation. The fixture is corrected and
  the assertion that was never there — that the tokens are gone — is.

- **A Security Event Token whose replay check could not run was applied
  anyway.** `handleSSFReceive` asks whether it has already seen a SET's `jti`
  for this tenant before applying it. No row is the *normal* answer there and
  arrives as `pgx.ErrNoRows`, and the read discarded its error — so "already
  seen", "never seen" and "the check did not run" were one value, and the third
  meant a re-delivered CAEP event was applied a second time. The comment on the
  *write* half of the same protection already recorded that its error had been
  discarded and was fixed; the read was left. It now tells `ErrNoRows` from a
  real failure and answers `503` when the check cannot run, because applying an
  event you cannot check for replay is the unsafe direction and a transmitter
  will re-deliver. Three more of the same shape: a **remote-support session**
  could be started while another was already running on the same agent when the
  concurrency check failed; the **posture checks a proxy route declares** were
  skipped in silence when the Ziti identity lookup failed (the score stays 0, so
  a policy requiring posture still refuses — the silence was the defect); and a
  **vault checkout ledger entry** — the record that a stored credential was used
  — went missing under a log line that named the insert rather than the reason.

- **The rest of the class: 55 more aggregate queries whose failure was served
  as a number.** `tools/zeroanswer`'s register is now **empty** — it opened at
  83, after `internal/audit` had already gone from 73 to 0, and every entry left
  it by the query being fixed rather than by being waived. The certification
  campaign page reported a campaign with nothing in it when its item counts
  failed, and drew a progress bar from `(certified+revoked)/total` where any of
  the three could be the false zero; `campaign_runs.total_items`, the permanent
  record of how big a review was, took a failed count as **zero items** — a
  certification with nothing to certify, according to its own record. An
  escalation whose "does this approver already exist" check failed added a
  **duplicate pending approval**, and that INSERT's error was discarded too, so
  neither was recorded anywhere. The authentication, usage, feature-adoption,
  capacity, AI-agent, recommendation, entitlement and sign-in analytics all
  answer 500 now instead of rendering zeros the console cannot distinguish from
  a quiet week. The remaining fail-closed checks — known device, known IP, the
  PAM quick-link existence gate — keep failing closed and now say so, because a
  control that silently degrades is a control nobody knows has degraded.

- **A failed query rendered as a calm number on every surface that counts
  something.** Twenty-four sites of the class above, found by
  `tools/zeroanswer`. The pagination totals — published apps, proxy routes,
  known devices — served `0` in the same response that carried the rows, so a
  list did not know its own length and paging past the first page looked
  impossible. The Relations & Integrity Doctor reported **`ok`** for a check it
  could not run, which is the one answer an integrity check must never give
  from no evidence. The end-user's own security page told somebody who has
  enrolled MFA that they have none, and reported no risky sign-ins because it
  could not read them. The risk dashboard's six tiles rendered *"0 high-risk
  logins, 0 failed logins, average risk 0"* — indistinguishable from a quiet
  day, on the surface where an operator decides whether to look further. And in
  the **risk engine itself**, four of the five scored factors bias *harsher*
  when their query fails (an unreadable device count reads as a new device) but
  one biases *quieter*: a failed count of recent failed logins removed the
  brute-force signal from the score entirely. Factors that cannot be measured
  are still scored from zero — inventing a number would be worse — but they are
  now logged by name, so an engine running on fewer factors than it thinks is
  visible instead of silent. This engine has already been caught running with a
  factor permanently at zero: the WebAuthn count read a table no migration
  creates, for the life of the query.

- **A failed count auto-completed an access certification campaign.**
  `handleDecideAttestationItem` counted the campaign's still-pending items to
  decide whether the last decision had been made — and discarded the error, so a
  query that could not run left the count at zero, marked the campaign
  `completed`, stamped `completed_at` and published `review.completed` to
  whatever evidence pipeline was listening. An access certification closed
  without the access being certified, with an audit trail saying it was. Two
  more in the same class: `continuous_auth`'s **velocity risk scored 0** when
  its query failed (the comment directly above it already recorded that this
  factor scored 0 for its *entire life* because it read a table that does not
  exist — the query was fixed, the discarded error that hid it was not), and
  `campaign_runs.reviewed_items`, the permanent record of how much of a
  certification campaign was reviewed before it expired, took a failed count as
  **zero reviewed** rather than leaving the column alone.

- **A compliance report could be produced entirely out of measurements nobody
  took.** Every figure in the SOC 2, ISO 27001 and GDPR reports came from an
  aggregate — `COUNT`, `SUM`, `AVG`, `MAX` — and every one of those queries
  discarded its error. An aggregate returns exactly one row, always, so a
  failed `Scan` there can never mean "there is no data": it means the query did
  not run, and the destination kept its zero. The report then published that
  zero as a measurement. *"0 overdue access reviews." "0 data-subject requests
  outstanding." "Average session length: 0 hours."* — in a document an auditor
  reads as evidence. This is not hypothetical: two queries in this file named
  columns the schema does not have (`access_reviews.due_date`,
  `sessions.created_at`), and both were found by a tool that plans the SQL, not
  by anything in the reporting code, because nothing in the reporting code was
  looking at the error. A third failure mode needed no broken query at all —
  the organization was read as `org, _ := orgctx.From(ctx)`, so a report
  generated without a tenant filtered every metric on an empty `org_id` and
  came back all zeros. Each section now runs through `metricQuery`, which
  remembers the first measurement that could not be taken and names it; a
  section that cannot be measured fails the report and the endpoint answers
  500, because a compliance report is the one document where *"I could not
  measure this"* must never be rendered as a measurement. The two grouped reads
  behind ISO 27001 A.12 are the same defect in multi-row shape — an `if err ==
  nil` around the loop meant a failed query left the per-day breakdown empty,
  which is a **logging coverage of 0%** and a `non_compliant` verdict on the
  strength of a query that never ran. **The tests that covered all this could
  not fail:** three of them built a service with no database at all, generated
  all three reports and asserted things like `TotalUsers >= 0` — true of the
  zero value, which was the only value any field ever held. They are replaced
  by one test that asserts the refusal, and by a real-schema test that
  generates all three reports against a migrated database and checks the
  numbers against seeded rows.

- **The detailed SOC 2 and ISO 27001 assessments scored controls from figures
  nobody measured** — the same defect as above, in the eleven control
  assessors behind `POST /audit/reports/soc2-detailed` and
  `.../iso27001-detailed`. Thirty-five aggregate queries, every error
  discarded, and the resulting numbers went into a control's **Evidence**
  lines (`"Total active users: 0"`, `"Active API keys: 0, Expired but not
  revoked: 0"`), its **score**, the report's overall percentage and its summary
  sentence. A control assessed from a query that did not run is
  indistinguishable, in the finished document, from one assessed from real
  data. Each assessor now returns the measurement failure and the report is
  refused. Nothing had been driving those two generators at all; a real-schema
  test now produces both and cross-checks a control's evidence against a count
  it takes from the database itself. Also fixed there: **ISO 27001 A.12
  required an event type this product has never written.** Its list of
  required audit event types was `authentication`, `authorization`,
  `user_management` — and `user_management` is a *category*; the event type
  stamped on a user lifecycle row is `identity`. So A.12 deducted ten points
  and reported *"Required event type 'user_management' has no events in
  period"* against every installation ever assessed. A control that
  manufactures a finding against a correctly configured system is worth less
  than no control. And in `internal/audit/service.go`, the four counts printed
  into the SOC 2 findings' evidence (`"%d/%d users have MFA enabled; %d failed
  auth attempts in period"`) and the security dashboard's failed-authentication
  count — which reads as *"no attack in progress"* when it is really *"the
  query broke"* — are checked as well.

- **Every audit event the access service posted was filed under the default
  organisation, and a refusal was silent.** `internal/access.logAuditEvent` is
  how the most sensitive actions in the product reach the audit trail — every
  revealed PAM credential, every injected credential, every downloaded session
  recording and transcript, every proxy allow and deny. It sent no tenant
  signal at all. The ingest endpoint (`POST /api/v1/audit/events`) is
  server-to-server and carries no JWT, and `cmd/audit-service` mounts
  `TenantResolver` globally with `router.Use`, which — as that middleware's own
  comment states — means its JWT and `X-Org-ID` steps cannot fire and every
  request lands on step 1 or the step-4 default-organisation fallback. With no
  header, always step 4: on a multi-tenant install the product's most sensitive
  reads were missing from the audit log of the tenant they belonged to and
  present in another's. The POST now carries `X-Org-Slug` — step 1, which
  *looks the slug up*, so an unknown one is a `400` rather than a free write
  into an arbitrary tenant. The response status was also thrown away: only a
  transport error produced a log line, so a `400` for a body the trail refused
  or a `500` when the write failed dropped the row with nothing recorded
  anywhere. A non-2xx is now a warning naming the status, the action and the
  tenant, because a dropped audit row is the one loss that must never be
  silent.

- **Six of the audit log's eight filter choices returned an empty list.** The
  console's event-type filter offered eight names copied from the `EventType`
  constants in `internal/audit/service.go`, and only two of them —
  `authentication` and `authorization` — are ever written. Choosing
  `user_management`, `group_management`, `role_management`, `configuration`,
  `data_access` or `system` returned nothing, and an empty audit list reads as
  *"nothing happened"*, which on this surface is the worst available wrong
  answer: an auditor asking for every configuration change was told there were
  none. Meanwhile the values the trail does hold — `identity`, `provisioning`,
  `oauth`, `access`, `security`, and the specific rows `internal/access` writes
  one at a time (`pam.session.risk_suspend`, `pam.recording.sealed`,
  `certificate.rotate`, `session.revoked.continuous_verify`,
  `platform_admin_cross_org_access`) — could not be filtered for at all. The
  filter now reads `GET /api/v1/audit/event-types`, which asks the tenant's own
  trail and returns each type with its count, ordered by frequency: what is
  offered is what is there. A catalogue would have to be kept in step with
  twenty writers by hand, and the drift it replaced is exactly what that costs.
  **Migration v180** adds the `(org_id, event_type)` index that scan and the
  filtered read both want — every read of `audit_events` is tenant-scoped
  first, so the console's own `WHERE org_id = $1 AND event_type = $2` had been
  walking every row of that type across the whole install and discarding the
  other tenants'.

- **The GDPR report's data-access section counted an event nothing writes** —
  and an earlier commit on this branch said it was fixed when it was not. All
  four of its queries filtered `event_type = 'data_access'`, a value declared as
  `EventTypeDataAccess` in `internal/audit/service.go` and written by no line of
  this codebase, so total access events, access by actor, access by data type
  and the last access timestamp were empty on every report ever generated and
  `ComplianceStatus` was permanently `"partial"` — a control telling an auditor
  this installation cannot account for who read what. The earlier fix corrected
  the by-data-type query, which asked for a `resource_type` column
  `audit_events` does not have, and the commit message said the section "has
  therefore been empty in every report". The column was **one** reason and not
  the reason. What this trail records as a read is an action under
  `event_type = 'authorization'`, and `internal/audit.DataAccessActions` now
  names the five that are one — a revealed credential, an injected credential on
  either path, a downloaded session recording or transcript — with the session
  events that are *not* reads named as deliberately excluded, because an
  overstated control is as useless as an empty one. The test that covered this
  had seeded a `data_access` row: it built the value the product never produces
  and then proved the query could find it. It now seeds the row
  `internal/access` actually writes.

- **Every switch on the notification preferences page controlled nothing.**
  The page offered seven types — `access_request`, `security_alert`,
  `session_revoked`, `review_assigned`, `group_request`, `password_expiry`,
  `mfa_change` — and this product has never sent a notification of **any** of
  them; the four it does send (`access_granted`, `device_trust`, `security`,
  `broadcast`) appeared on no switch, and one column offered a channel,
  `email`, that nothing has ever delivered on. It was worse than a naming
  mismatch: `isNotificationEnabled` is consulted by `CreateNotification`, and
  four of the six senders never went through it — the broadcast fan-out, the
  ISPM MFA reminder, the AI-recommendation reminder and the device-trust
  request all ran `INSERT INTO notifications` directly as set-based writes. A
  preference no writer reads is not a preference, however it is spelled. Each
  of those statements now carries the preference predicate itself, measured
  against a real database: the user who switched security reminders off
  receives none, the user who never opened the page receives them, because an
  absent row means enabled — the same default `isNotificationEnabled` applies.
  `internal/notifications.TypeCatalogue` is now the one place a type is named,
  `GET /notifications/preference-types` serves it, the console's picker reads
  it instead of its own stale list, and `PUT /notifications/preferences`
  refuses a preference for a type this deployment does not send. The lookup
  behind that default is no longer silent either: `isNotificationEnabled`
  answered *every* failure — a missing table, a permission error, a dead
  connection — with "enabled", so a preferences store that had stopped working
  was indistinguishable from a population that had simply never opened the
  page. A failed read still sends, because nobody should stop being told their
  device was approved by a broken query, but only `pgx.ErrNoRows` is the quiet
  default now; anything else is logged.

- **The migration chain could not be rolled back past v29.** Every migration
  carries a `Down` half and `RollbackTo` exists to run them — it is what an
  operator reaches for when an upgrade goes wrong — and nothing had ever
  executed the chain in that direction. Measured on a fresh PostgreSQL 16,
  rolling back from v179 one version at a time, it stopped at v29 with
  `DROP TABLE IF NOT EXISTS posture_check_types;` →
  **`ERROR: syntax error at or near "NOT"`**: a spelling PostgreSQL has never
  accepted (the keyword is `IF EXISTS`), in five statements across three
  migrations. Behind that, at v13 and v10, nine more statements matched a UUID
  primary key with `LIKE`, which raises
  `operator does not exist: uuid ~~ unknown`. So the rollback path was blocked
  at v29 on every install, and the twenty-nine migrations below it had never
  been reachable in reverse at all. All fourteen statements are fixed and the
  chain now completes the full round trip: 179 up, 179 down to zero, 179 up
  again. **A new test does exactly that** against a throwaway container, and
  asserts the schema left behind after a full rollback is exactly the four
  tables it should be — the migrator's two bookkeeping tables plus the two v51
  re-creates on the way down, which is recorded rather than papered over.
  `scripts/check-test-reachability.sh` was widened in the same change: it
  matched one literal variable name, so a helper gating on a private
  `OPENIDX_*_DATABASE_URL` of its own was invisible to it — the guard failing
  in the way it exists to prevent.

- **The OpenID Connect discovery document omitted three things this server
  does.** `revocation_endpoint` and `introspection_endpoint` (RFC 8414 §2) were
  absent although `POST /oauth/revoke` and `POST /oauth/introspect` are both
  routed, so a relying party that reads discovery to find where to revoke a
  token at sign-out found nowhere — and did not revoke. And
  `token_endpoint_auth_methods_supported` listed only `client_secret_post` and
  `client_secret_basic`, although dynamic client registration creates a
  **public** client when `token_endpoint_auth_method=none` and the token
  endpoint skips secret verification for that type (PKCE carries the proof
  instead): every conforming SPA and native client was told it had no usable
  authentication method here. All three are now advertised, and they move with
  the issuer under subdomain tenancy. The drift was invisible because it was on
  the wrong side of a dead file: `api/openapi/oauth-service.yaml` documented
  both endpoints, `docs/docs/api/authentication.md` showed them in its sample
  document, and `internal/oauth/discovery.go` — a **second, unmounted**
  discovery implementation with a 415-line test suite — carried them too. Only
  the document actually served lacked them. The dead implementation is deleted
  and its assertions moved onto the live handler, so a discovery test now goes
  through the route a relying party fetches.

- **Six of the webhook events the console offers had never been published.**
  The subscription form listed ten event types. `user.updated` and
  `group.updated` were emitted only from `internal/identity/handler.go` — a
  complete second user-and-group CRUD implementation, fourteen exported
  handlers, that **no router has ever mounted** — so their emitters ran
  nowhere. `user.locked`, `login.failed`, `role.updated`, `policy.violated` and
  `review.completed` were emitted by nothing at all: the failed-login path wrote
  an audit row and sent no webhook, an account lockout was logged and announced
  to no one, and a completed access-certification campaign told nobody. An
  operator wired an integration up, saw the subscription listed, saw the
  delivery log stay empty, and had no way to tell that from a quiet week. Every
  one now publishes from the handler that actually runs: `user.updated` and
  `user.deleted` from the mounted user handlers, `user.locked` on the failed
  attempt that crosses the lockout threshold (once, not on every retry after),
  `login.failed` beside the audit row, `role.updated` from the role handler,
  `policy.violated` when the ABAC gate denies a sign-in, `review.completed` when
  an attestation campaign's last item is decided — and the four group events
  that had no publisher and no constant, `group.created`, `group.deleted`,
  `group.member_added` and `group.member_removed`, the last being the event a
  downstream system needs in order to **revoke** the access that came with a
  group. Publishes are now made on a context detached from the request but
  carrying its organization (`orgctx.Detached`): webhook subscriptions are
  RLS-scoped, so an org-less publish matches nothing and delivers nothing,
  quietly, for every tenant. `internal/identity/handler.go` is deleted.

- **Revoking a user's MFA break-glass codes has never revoked one.**
  `DELETE /users/:id/bypass-codes` is how an administrator destroys every MFA
  bypass code a user holds — what you do the minute a break-glass code leaks.
  Its handler opened `requestedUserID := c.Param("user_id")`, and the route
  declares `:id`. gin returns `""` for a name the matched route does not
  declare, so the revoke ran against the empty user and PostgreSQL refused the
  statement outright (`mfa_bypass_codes.user_id` is `UUID`): every call this
  endpoint has ever received answered **400 `invalid input syntax for type
  uuid: ""`**, worded as though the administrator had sent something wrong. The
  handler now reads `c.Param("id")`, and a new DB-backed test drives the real
  route: two active codes for the target are revoked, a third belonging to
  somebody else is left alone, and the `revoked_all` entry lands in
  `mfa_bypass_audit`. Proved red first with exactly the failure above.

### Added

- **`tools/sqlprepare` no longer skips `42P08`.** "Inconsistent types deduced
  for parameter" was on the skip list beside `42P18`, described as a limit of
  `PREPARE`. It is not one: pgx sends parameters **untyped**, so the deduction
  the sweep performs is the deduction the runtime performs, and a statement
  that cannot settle on one type for a parameter fails when it is executed. The
  skip hid a live failure — an `INSERT ... SELECT` written in this same change,
  reusing one parameter for `notifications.type` and
  `notification_preferences.event_type`, passed the sweep and raised
  `inconsistent types deduced for parameter $5` on its first execution against
  a real database. Five statements were caught and cast the moment the skip was
  removed; `42P18`, where the server genuinely has nothing to deduce from,
  stays a skip.

- **A webhook event catalogue that cannot drift from the code.**
  `internal/webhooks.EventCatalogue` is now the single place an event type is
  named — type, category, and the sentence an operator reads when choosing what
  to subscribe to — and `catalogue_test.go` holds it against the tree in **both
  directions**: an entry nothing publishes fails the build, and a `Publish`
  naming something outside the catalogue fails it too. The census resolves
  literals, `webhooks.EventX` constants, a variable assigned two constants, and
  one level of forwarding (a helper that takes the event type as a parameter is
  resolved at its call sites), and a `Publish` whose event type it cannot read
  is itself a failure in the services that own a publisher — so nothing can hide
  behind an expression. `GET /api/v1/webhooks/event-types` serves the catalogue
  and the console's picker now reads it instead of a hard-coded list that had
  drifted six entries away from reality; `POST /api/v1/webhooks` rejects a
  subscription to an event type this deployment does not publish, with the
  endpoint to consult, because the moment a subscription is created is the only
  moment an operator can be told.

- **`tools/routereach` — parameters with no route, handlers with no router.**
  The census that found the defect above, and a second class beside it. It
  holds each service's route table next to the handlers its package defines and
  reports two disagreements: a handler that reads `c.Param("x")` when no route
  it is mounted on declares `x`, and a `func(*gin.Context)` that no route
  registration names and no non-test line references. Reachability is
  propagated to a fixpoint through same-package calls, so a helper handed the
  request context is checked against the routes of every handler that can reach
  it, and the parameter sets of a handler's routes are unioned rather than
  checked one at a time. The parameter check is exact here because no `.Group()`
  prefix in this tree declares a parameter — asserted against the real sources
  by the tool's own test, not assumed. **`_test.go` files are deliberately not
  scanned**: a handler whose only caller is a test that mounts it on a router
  the test built is the sharpest form of the second finding, and that is how
  `internal/oauth`'s second OpenID Connect discovery document came to light —
  415 lines of passing test for a document no service serves, beside the
  different one every relying party actually fetches. 1,060 routes, 1,021
  handler-shaped functions, **17 mounted by nothing**, each registered in
  `tools/routereach/known.go` with its verdict; a route that declares
  parameters and resolves to no handler is itself a finding, because a census
  that quietly stops covering something is the failure these registers exist to
  prevent. Wired as a required check (`Route-reachability lint`).

- **`tools/tablewriters` — the tables the product reads and nothing writes.**
  The API-usage card reads `api_usage_metrics` for total requests, average
  latency and error rate; migration v54 created that table with exactly the
  columns an hourly request aggregate needs, and nothing has ever inserted a
  row into it. So the card has reported three zeros on every install that has
  ever run, and a zero from an empty table is indistinguishable from a measured
  zero. Nothing else in the repository can see this: the SQL is valid, so
  `sqlprepare` passes it; the tenant predicate is present, so `orgscope` passes
  it; the handler returns 200 with a well-formed body, so the contract test
  passes it; and `COUNT(*)` of an empty table is 0, not an error, so nothing is
  logged. The only thing that can see it is a census, so this one holds the set
  of tables the migration registry creates next to the set of tables a SQL
  literal in `./internal`, `./cmd` and `./pkg` writes, and subtracts. Both
  halves are derived rather than listed, for the reason `orgscope` was
  inverted. Literals come out of the AST rather than a grep, because prose
  about SQL is not SQL — a comment quoting a query a previous fix deleted was
  read by the first draft as a live read of a table dropped two migrations ago.
  A table a migration seeds is not a finding: the seed is its writer. **Nine of
  226 live tables have no writer**, each registered in
  `tools/tablewriters/known.go` with its verdict, and the register can only
  shrink: an unregistered finding fails the run and so does an entry that no
  longer reproduces. Five are read — `api_usage_metrics`, `risk_factors` (the
  continuous-auth engine computes five weighted factors and returns the empty
  slice it started with), `ai_agent_activity` (three reads: a per-agent
  activity list, a 24-hour ranking and a failure count, all empty because
  nothing outside the admin API so much as reads an agent credential, so no
  agent has ever acted), and `upstream_pools` with its members (v130 built the
  place to express a load-balanced backend set and the reconciler that renders
  it; nothing can create one). Four are dead schema: `health_check_history`,
  `posture_check_types`, `scim_groups` — the unused half of v3's SCIM pair,
  whose install-wide unique key an earlier commit in this programme carefully
  re-scoped — and `user_mfa_policies`.

- **`tools/sqlprepare` — every SQL literal in the tree, planned by a real
  PostgreSQL.** A green CI run's database log carried `column "request_count"
  does not exist`, and following it found a class no reviewer or compiler can
  catch: a query naming a column that has never existed is syntactically
  perfect Go and SQL, and the handler around it discards the error. The tool
  hands each statement to `PREPARE` against a database with all migrations
  applied — parse, name resolution and planning, no execution and no rows — so
  a missing column, a missing table, an unresolvable type or an aggregate
  outside its `GROUP BY` surfaces and nothing else does. Syntax errors are
  skipped as fragments of runtime-assembled queries and parameter-inference
  errors as limits of `PREPARE` itself; a file the sweep cannot parse fails the
  run rather than quietly shrinking the count. It runs in the integration job,
  the only place with a migrated database. The first sweep found **39
  statements that cannot succeed against the schema this repo creates**, each
  registered in `tools/sqlprepare/known.go` with its verdict; a finding the
  register does not carry fails the run, and so does an entry that no longer
  reproduces, so the list can only shrink. Among them: no security alert has
  ever been written (`security_alerts` has none of the six columns the INSERT
  names), the SIEM forwarder's cursor table is created by no migration,
  scheduled-report listing fails outright, the DSAR export silently omits
  sections, two compliance controls report zero findings because api-key
  revocation lives in `status` and not a `revoked_at` column, and the API-usage
  dashboard's four queries all name columns that were never created — so it
  reports 0 requests, 0 errors and 0 ms latency as measurements.

### Removed

- **Four tables no code has ever touched (migration v177).** The other half of
  what the census found: `health_check_history` (v54), `posture_check_types`
  (v29), `scim_groups` (v3) and `user_mfa_policies` (v5) are read by nothing and
  written by nothing, and between them carry DDL, indexes, grants, foreign keys,
  row-level-security policies and a docker seed that maintains five rows nobody
  consults. `scim_groups` is the unused half of its SCIM pair — `scim_users` is
  written on every SCIM user operation, group provisioning writes the product's
  own `groups` table — and an earlier commit in this programme carefully
  re-scoped its install-wide unique key, which is what dead schema costs: it
  consumes the attention the real tables need. Two of the four sat behind the
  v37 FORCE-RLS belt, which is the argument for dropping rather than leaving:
  a belted table with no rows looks, to every census here, like a tenant
  boundary being maintained. The rollback recreates all four in the shape the
  chain had produced — org_id, foreign key, index, policy and the re-scoped
  unique key included — read off a database with the full chain applied.

- **The Usage Analytics API card, and the table behind it (migration v176).**
  `api_usage_metrics` was created by v54 with exactly the columns an hourly
  request aggregate needs, and no handler, worker or seed has ever inserted a
  row. The card read it for total requests, top endpoints, error rate and
  average latency, so all four have been 0 on every install that has ever run —
  and the read could not have worked either, naming three columns the table does
  not have. Request volume, latency and status codes *are* measured: the
  Prometheus middleware every service mounts exports them on `/metrics`, for the
  Prometheus and Grafana this repo ships. A second copy aggregated into Postgres
  was never written, and writing that aggregator is a feature rather than a fix,
  so the endpoint, the console card, its i18n keys and the OpenAPI path go with
  the table.

### Fixed

- **The SQL register is empty: every statement in the tree now plans against
  the schema.** The last four. `oauth_clients.redirect_uris` is JSONB and the
  BrowZer domain rewrite called `unnest()` on it, so after a domain change every
  OAuth client kept redirecting to the old domain — the exact failure a domain
  change exists to prevent. The bulk-access anomaly's "breakdown by resource
  type" asked `audit_events` for a `resource_type` column (it is `target_type`)
  and discarded the error, so every anomaly this detector raised named nothing.
  Migration **v179** gives `saml_service_providers` the `metadata_xml` column
  its refresh has always written to: without it the whole UPDATE failed to plan,
  and with it the only path by which a service provider's **rotated signing
  certificate** reaches this database — an administrator clicked refresh, got an
  error, and assertions kept being signed against the old certificate. The
  fourth was another false positive of the tool, now fixed there: the
  access-review roll-up's literal is the first half of a query the code appends
  a `GROUP BY` to, and `sqlprepare` prepared it alone and reported a grouping
  error for a query that groups correctly at runtime. It now recognises a
  literal the code appends to and skips only the errors a suffix can explain — a
  missing column or table on such a fragment is still a finding.

- **The console's tenant switcher has never worked, and nine other statements
  the database refused.** `handleSwitchTenant` and `handleGetCurrentTenant`
  selected `display_name` and `enabled` from `organizations`, which is
  `(id, name, slug, domain, plan, status, …)` and has neither; both handlers map
  any error from that row to 404, so switching tenant answered "Organization not
  found" for every organization that exists — a feature that reads to whoever
  hits it as a permissions problem. A **joiner rule that granted nothing**: the
  lifecycle `assign_role` action inserted into `user_roles` with a `created_at`
  column (the table records `assigned_at`), so no automated rule has ever
  assigned a role, on any install. **Zero dormant accounts** on the security
  posture card, because the count asked for `users.last_login` and the column is
  `last_login_at` — zero is the answer that makes the card look best. A
  **biometric policy targeted at a role matched nobody**, because the role
  lookup selected a `roles` column from `users` (roles are rows in `user_roles`).
  Plus the top-failed-users list (uuid into a varchar `COALESCE`), the push-MFA
  enrolment label (one parameter used as both text and uuid), the API-key
  adoption figure (`revoked_at` again), the churn-prediction input, and the risk
  profile's average session duration (`sessions.created_at` → `started_at`).
  Each was found by `tools/sqlprepare`; the tenant switch and the lifecycle
  action are covered by new tests that run the real migration chain, both proved
  red first. One register entry went the other way and is **withdrawn**: the
  unified-audit reader's SELECT list, which the code uses as the search argument
  of a `strings.Replace` that swaps it for `COUNT(*)`, was prepared as though it
  were a statement and written up with a verdict that was true of nothing.
  Measured since: the replacement fires and the count query it builds is valid.
  `sqlprepare` now skips a "missing FROM-clause entry" on a literal that has no
  FROM clause — a SELECT list is not a statement — while a missing *table*,
  which always comes from a statement that has the FROM clause naming it, stays
  a finding.

- **Four compliance controls that reported compliant because their queries
  could not run.** Six statements across the SOC 2 / ISO 27001 / GDPR reporting
  named columns the schema does not have, and each failed silently into a zero.
  `access_reviews.due_date` (the deadline is `end_date`) — the overdue-review
  count read 0 on every report ever generated, so the dashboard stated that no
  access review was overdue. `sessions.created_at` (it is `started_at`), twice —
  average session length always 0 hours, so the "sessions run too long" control
  never fired. `audit_events.resource_type` (it is `target_type`) — the GDPR
  report's access-by-data-type section was empty in every report.
  `api_keys.revoked_at` (revocation is `status`), in **both** halves of the
  expired-key control — an install with expired keys still being accepted
  reported zero findings and lost no points. A control that cannot fail is not a
  control, and zero findings reads to an auditor as evidence. Migration v178
  retires v10's seeded "Q1 2026 Access Review" fixture where it is untouched:
  with the overdue query corrected, that pending row dated March would otherwise
  give every install a permanent overdue finding no operator created and none
  could close. Pinned by a new suite that runs the real migration chain rather
  than creating its own tables — the sibling DB tests in that package define the
  columns they then assert on, which is part of why these six survived.

- **The right to erasure had never run, and the data package always omitted
  four sections.** Both halves of the GDPR subject-rights implementation were
  broken in the same way, and neither could be seen from outside. *Erasure
  (Article 17):* the statement that anonymises the user row set `phone_number`
  and `avatar_url`, neither of which exists on `users`, so it failed with
  SQLSTATE 42703 — and being the **first** statement, its error was returned
  before a single session, MFA enrolment or consent was wiped. No erasure
  request has ever run to completion on any install. *Export (Article 15):* four
  of the twelve categories named columns the schema does not have —
  `audit_events.resource_type` (it is `target_type`), `mfa_totp.verified_at`
  (`enrolled_at`), `mfa_webauthn.friendly_name` (`name`),
  `mfa_push_devices.device_type` (`platform`/`device_name`/`device_model`) — and
  each failure was logged at Debug and the section left out, while the result
  reported `categories: 8` as though eight were all there were. The subject's
  own activity log and all three MFA enrolment records were missing from every
  data package this product has produced. Both are fixed against the real
  schema, and both now say when they cannot do what they claim: a category that
  fails is named in the bundle under `_incomplete` and counted in the response,
  and a failed erasure statement returns an error instead of marking the request
  completed. The erasure also now wipes the tables that actually hold a phone
  number (`mfa_sms`, `mfa_phone_call`, `phone_call_challenges`) and the device
  records (`known_devices`, `trusted_browsers`) — the "no leftover phone numbers
  / device IDs" its own comment has always promised — and the export gained
  those four as categories. Driven end to end by a new test against a migrated
  database, proved red first on both halves.

- **A risk score with nothing behind it.** The continuous-auth engine computes
  five weighted factors — session age, source-address change, device
  fingerprint, out-of-hours activity, action velocity — sums them into a 0-100
  score, and returned `RiskFactors` exactly as empty as it was initialised, on
  every response, while writing the literal `{}` into
  `session_risks.risk_factors`, the column that exists for that detail. A score
  of 45 that cannot say which factor produced it is not evidence for the step-up
  it triggers. Each factor is now recorded as it is measured — type, raw points,
  the deployment's weight, the weighted share of the scale, and a sentence
  saying what was measured — and travels with the score, in the response and in
  the history row under a `source` discriminator so the column's two writers can
  be told apart. The v77 `risk_factors` table it should have been written to is
  dropped by v176: nothing ever wrote it, its only reader had no caller, and the
  one test that exercised that reader seeded the rows itself. The replacement
  test drives the whole path, from a measurable condition to the factor list on
  the score and in the stored row.

- **The SQL gate added in this release could not fail the build.** ci.yml's
  integration step opens `set -uo pipefail` — no `-e` — so a bare failing
  command does not stop the script and the step's exit code is whatever the
  LAST command returned. Measured: `bash -c 'set -uo pipefail; false; echo
  reached; true'` prints `reached` and exits 0. `go run ./tools/sqlprepare
  -fail` was added as a bare command, so it would have printed its findings into
  a green job — the defect this branch keeps finding, written into the file
  whose job is checking. It and `go run ./cmd/migrate up` now say `exit 1`
  themselves, the four service builds in the same block are guarded (an
  unbuilt service surfaced sixty seconds later as "services did not become
  ready", naming the wrong cause), and
  `scripts/check-run-blocks-can-fail.sh` keeps the next one honest: in a
  block that sets shell options without `-e`, a gating command must be
  guarded unless it is the last command, whose status *is* the step's. Eight
  self-test cases, five of them negatives (`|| true`, a `-e` block, no `set`
  line, the last command, non-gating commands).

- **The SIEM forwarder created its own cursor table, as a role that cannot
  create tables.** `internal/audit/siem_forwarder.go` opened with
  `CREATE TABLE IF NOT EXISTS siem_forward_cursor` executed through the service
  pool, which connects as `openidx_app` — the runtime role v53 created without
  DDL rights. Measured against a fully migrated database:
  `has_schema_privilege('openidx_app','public','CREATE')` is false. So the
  statement always returned "permission denied for schema public" and every
  poll after it failed on a missing relation: audit events have never reached a
  SIEM on any install that uses the app role, which is every deployment this
  repo ships. The least-privilege work and this forwarder were each correct
  alone and were never read together. Migration **v175** creates the cursor and
  grants the forwarder exactly SELECT, INSERT and UPDATE on it; the runtime DDL
  is replaced by a read that says once which migration is missing.

- **Listing scheduled reports failed outright**, and silently: `recipients` is
  `TEXT[]` and the query COALESCEd it with the JSON literal `'[]'`, which
  PostgreSQL rejects while planning, while the error path answers an empty slice
  and a nil error — so the page was empty rather than broken.

- **No access request had ever been auto-approved.** `access_requests.
  resource_id` is a UUID and the lookup COALESCEd it with `''`, resolved at plan
  time, so the query errored on every call.

- **No security alert had ever been written, on any install.**
  `internal/risk/alert.go` INSERTs twenty-one columns into `security_alerts`
  and six of them do not exist — `tenant_id`, `ip_address`, `user_agent`,
  `deliveries`, `acknowledged_by`, `acknowledged_at` — so the statement has
  never executed since it was written. The single-alert read, the list and the
  acknowledge path named the same absent columns, so the alerts page would have
  been empty even if a row had arrived some other way, and the failure surfaced
  only as an error the caller logged. Two of the six were a naming
  disagreement: `tenant_id` is `org_id`, which the same statement already set
  (the file's own comment claimed the table "carries both", which was never
  true of the schema), and `ip_address` is `source_ip` — a caller that filled
  only `IPAddress` would have written an empty address even once the statement
  ran. Migration **v174** adds the other four, which are real fields with
  nowhere to go, plus an index for the list the page issues. The second writer
  needed no columns at all: `internal/audit/anomaly.go` INSERTed `type`,
  `event_id`, `actor_id`, `timestamp` and `metadata` — the audit-events
  vocabulary applied to this table — and every one maps onto a column that was
  already there, so a detected anomaly now raises an alert instead of logging
  that it could not. Found by `tools/sqlprepare`; the register is down from 39
  to 34.

- **The agent module was scanned for vulnerabilities against the wrong Go
  standard library, and it was the toolchain-pin change that did it.**
  `go-version-file` reads go.mod's `go` directive, not its `toolchain`
  directive, so pointing every `setup-go` step at the root go.mod installed Go
  1.26.0 rather than the pinned 1.26.8. The root scan was unaffected — the
  `toolchain` line makes the go command re-exec 1.26.8 — but Go only ever
  switches *up*, so the agent, pinned to 1.25, kept the installed 1.26.0 and
  govulncheck reported the 19 advisories that release carries and 1.26.1 fixes,
  two of them reachable from the agent's own SSO path. Before the pin change
  the loose `'1.26'` spec happened to resolve to the runner's cached 1.26.7,
  which is the only reason this was ever green. The agent scan now gets its own
  `setup-go` reading `agent/go.mod`, and
  `scripts/check-go-toolchain-pin.sh` gained two rules: a `go-version-file`
  must name a file that exists, and a step running in another module must be
  preceded by a `setup-go` for that module's go.mod. Eleven self-test cases,
  and the guard was shown red against the real workflow with the new step
  removed.

- **ABAC evaluation failed on every request, which under
  `ABAC_ENFORCE=enforce` denies everything.** `abac_policies.resource_id` is a
  UUID column and the policy query compared it to the empty string; PostgreSQL
  resolves that at plan time, so the statement never ran, the error became
  `Allowed: false`, and the evaluator answered "policy evaluation error,
  failing closed" for every call — in observe mode recording a would-deny on
  every request, and in enforce mode denying them. Found by `tools/sqlprepare`
  on its first sweep.

- **The trusted-proxy hardening resolved every client to the proxy's own
  address in the deployments this repo ships.** `ConfigureTrustedProxies` trusts
  loopback only, on the stated premise that "every service sits behind the edge
  and is reached over loopback". Neither reference deployment is: in
  `deployments/docker` the TLS proxy forwards with
  `proxy_pass http://oauth-service:8006` and the gateway proxies container to
  container, and under Helm an ingress pod forwards to a service pod — and
  `OIDX_TRUSTED_PROXIES` was set in no compose file, no chart value and no
  `.env.example`. gin walks `X-Forwarded-For` right to left and stops at the
  first untrusted address, so the edge's correctly written header was discarded
  whole and `c.ClientIP()` returned the hop. Everything keyed on the client IP
  therefore shared one value: the per-IP rate-limit bucket (including the
  tighter auth-path budget that exists to slow a brute force, since pre-auth
  requests have no user to key on), audit record IPs, known-IP device-trust
  auto-approval and geo rules. The default stays loopback — widening it would
  trust a forwarded header on installs whose services are directly reachable —
  but the mismatch is no longer silent: a request arriving from an untrusted hop
  with a forwarded header is logged once per hop, with the address to add, and
  counted in `openidx_forwarded_for_from_untrusted_hop_total` (alert
  `ForwardedClientIPDiscarded`). The detector is mounted from inside
  `ConfigureTrustedProxies`, so there is one call site to get right rather than
  eight. `OIDX_TRUSTED_PROXIES` is now passed through by the compose file,
  exposed as the chart's `config.trustedProxies`, and documented in
  `.env.example`. Existing installs behind a non-loopback edge should set it;
  the warning names the address.

- **Every CI job downloaded a Go toolchain it did not need, and one of those
  downloads failed the build.** `go.mod` pins `toolchain go1.26.8`; `ci.yml`
  asked `actions/setup-go` for `'1.26'`. The runner's tool cache holds 1.26.7,
  so setup-go reported "Successfully set up Go version 1.26" and the next `go`
  command fetched go1.26.8 from `proxy.golang.org` — roughly 70 MB, per job,
  unretried, on every run. Twelve jobs did this. On 2026-09-06 one of those TLS
  handshakes timed out and failed `Unit Tests (internal/notifications)` before a
  single test body ran, which reads as a test failure and was a CDN blip on a
  download that should not have happened. Every setup-go step now passes
  `go-version-file: go.mod`, so the pin lives in one place and the exact
  toolchain is installed directly. `scripts/check-go-toolchain-pin.sh`
  (self-tested, wired into the `ci-resilience-guards` job) fails on a version
  spec, including an exact one — two pins drift. The build matrix keeps its
  minor-version label because that string is part of a check name branch
  protection may require.

- **The gateway — the service that faces the internet — sent no security
  headers.** Seven of the eight HTTP service mains mount
  `middleware.SecurityHeadersForEnv`; `cmd/gateway-service` did not, and nothing
  in `internal/gateway` set one either. So the one host a browser actually talks
  to answered with no HSTS, no `X-Content-Type-Options: nosniff`, no
  `X-Frame-Options`, no `Referrer-Policy` and no CSP on everything it produces
  itself: `/metrics`, the combined OpenAPI spec, and every 404, 429 and 502 the
  proxy generates. Proxied responses carry the backend's headers, so the gap was
  the gateway's own. Verified against the real binary both ways — before the fix
  a gateway-generated 502 carried none of them, after it carries all six.
  Duplicate CSP on proxied responses is harmless and the code says why: the
  gateway forwards only the six `/api/v1` JSON groups, browsers enforce the
  intersection of repeated policies, and the Guacamole path overrides do not
  apply because those prefixes are not proxied here.
  The omission was invisible because seven services looked like the rule, so the
  list is now DERIVED: `TestEveryHTTPServiceMountsSecurityHeaders` finds every
  `cmd/` main that builds a gin engine and fails unless it mounts the headers or
  is declared exempt with a reason. `scripts/smoke-test.sh` asserts the same
  thing against the running gateway, because "mounted in main.go" and "on the
  wire" are two different claims.

- **The gateway's request-body logger truncated the request it was observing.**
  `internal/gateway/middleware/logging.go` read the body through an
  `io.LimitReader` and then handed the *truncated* bytes back to the handler, so
  turning on `LogRequestBody` would have silently cut every request over
  `MaxBodySize` before the code that had to act on it ever saw it — a logging
  option corrupting its own subject. It now reads the body in full, restores it
  in full, and applies the limit to what is *logged*. The body also went into
  the log verbatim on a path that carries passwords and authorization codes; it
  goes through `logsafe.JSONBody` now.

- **`logsafe.JSONBody` parsed an unbounded body.** Moving redaction ahead of
  truncation (see the entry below) meant the parser saw the whole body rather
  than the first 10 KB, and decoding into an `interface{}` tree costs several
  times the input. Input over 64 KiB is now reported by size and not parsed.
  Depth needed no separate bound: `encoding/json` refuses beyond 10,000 levels
  of nesting, which bounds the recursion before it starts. Raised by a Semgrep
  finding whose named CWE (502, unsafe deserialization) does not apply to Go's
  `encoding/json` — but the concern underneath it did.

- **The OAuth authorization code was written to the log in clear, on every
  callback, by every service.** Three request loggers exist in this tree. The one
  in `internal/common/middleware` has redacted query parameters for its whole
  life and is mounted by nothing; the gateway's is mounted by nothing either. The
  one every service actually mounts -- `internal/common/logger.GinMiddleware`,
  used by `cmd/{identity,oauth,access,admin-api,audit,governance,provisioning,
  gateway}-service` -- logged `c.Request.URL.RawQuery` verbatim. Five callback
  routes read `code` from the query string (`internal/oauth/social_login.go`,
  `social_link.go`, `service.go`; `internal/access/service.go`, `multi_idp.go`),
  `internal/oauth/handlers_passwordless.go` reads the magic-link `token`, and two
  routes read `session_token`; all of them went into the log unredacted. The
  panic-recovery handler (`internal/middleware/recovery.go`) did the same, on the
  entry most likely to be forwarded to an error tracker. A control that exists
  only in the copy nobody runs is not a control.
  The redaction now lives once, in `internal/common/logsafe`, and all three
  loggers plus the recovery handler use it. A guard
  (`TestNoLoggerWritesARawQueryString`) fails on any raw query string reaching a
  log field, so which copy is mounted stops mattering.

- **The redaction itself missed the values worth redacting, and had a
  one-character bypass.** The list named secrets from memory: `access_token` and
  `refresh_token` were there, `id_token_hint` was not; `token` was there,
  `session_token` was not; `code`, `state`, `nonce`, `user_code`, `SAMLRequest`
  and `RelayState` were absent entirely. And the parameter name was matched
  BEFORE URL-decoding while the handler decodes, so the two disagreed about what
  a parameter was called: `?%74oken=hunter2` was read by the handler as
  `token=hunter2` and logged as `%74oken=hunter2`, in clear (measured). Names are
  now matched decoded, an undecodable name is redacted rather than trusted, and
  the exact list is only half the rule -- the other half matches by WORD, so
  `session_token`, `backup_code` and `provisioning_key` redact without anybody
  listing them. A census guard
  (`internal/common/middleware/query_param_census_test.go`) derives every query
  parameter the tree reads and requires each to be classified: redacted, or
  declared public with a reason. Ninety-four are classified today; a
  ninety-fifth cannot arrive unclassified.

- **`sanitizeJSON` failed open in three ways at once.** Its five "pattern
  variations" were three byte-identical duplicates plus one with a space, so
  `"password" : "x"` was missed; it redacted only the first occurrence of each
  pattern, so a second password survived; and it matched only a quoted string
  value, so a numeric pin, an array of recovery codes and a nested
  `{"credentials":{...}}` object went through whole. `LogBody` is off by default
  and no service sets it, so this never reached a real log -- it was a trap armed
  for whoever turned the flag on to debug something. It now parses the body and
  redacts by field name at any depth, in any container; a body that is not JSON
  is withheld with its size reported rather than guessed at. Related: sanitising
  ran AFTER the 10 KB truncation, and truncated JSON does not parse, so with the
  new implementation every large body would have been discarded whole. Redact
  first, cut second.

- **The correlation id every log line is stamped with was chosen by the
  client.** Seven places read `X-Request-ID`, `X-Correlation-ID` or
  `traceparent` off the request and adopted whatever arrived -- three
  `RequestID` middlewares (`internal/middleware/requestid.go` twice,
  `internal/common/middleware/logging.go`,
  `internal/common/middleware/middleware.go`), the gateway's correlation
  middleware and its `GetCorrelationID` fallback, and `TracingHeaders`, which
  relays them to the backend. That value is echoed back in the response, kept on
  the request context, written into every log entry for the request, and set on
  the outbound request to each service: a caller sending five kilobytes of "A"
  got five kilobytes back and five kilobytes per entry (measured, not
  hypothesised), and could equally pick an id that collides with somebody else's
  request. An inbound value is now adopted only when it is id-shaped --
  `logsafe.PlausibleID`, which accepts a UUID, a W3C traceparent and a vendor
  scheme, and rejects anything longer than 128 bytes or outside
  `[A-Za-z0-9-_.:]` -- and is replaced with a fresh UUID otherwise. Replaced,
  not cleaned: an id quietly rewritten still ties one request's entries together
  but no longer matches what the caller kept, which is the only job it has. One
  implementation now, and a guard (`TestCorrelationHeadersAreValidatedWhereThey
  AreRead`) that fails on an eighth copy -- the same lesson `logsafe` itself was
  created for, one level up.

- **`logsafe`'s own comment named the wrong mechanism.** It said zap's console
  encoder writes a newline raw where the JSON encoder escapes it, so a hostile
  value in a FIELD could forge a log line. Measured, that is backwards: the
  console encoder delegates fields to a JSON encoder, so a newline comes out as
  `\n` and an ANSI escape as `\u001b` under both. The half that is raw is the
  MESSAGE, so the forging shape is `logger.Warn(fmt.Sprintf("... %s", input))`,
  which the comment did not mention. Naming the wrong mechanism is worse than
  naming none -- it invites "just use the JSON encoder", which fixes nothing.
  The comment now says what was measured, `encoder_test.go` measures it (so the
  claim fails a build rather than ageing), and the reasons a field still needs
  cleaning are stated as what they are: the length bound no encoder applies, the
  sinks downstream of zap that do their own escaping or none, and the fact that
  a percent-encoded `%0A` in a request target really does arrive in
  `URL.Path` as a newline. A new guard forbids the interpolated-message shape
  outright; the tree had two (`internal/server/graceful.go`), now zero.

- **Request-derived values reached the log unfiltered across
  `internal/common/middleware`.** CodeQL flagged one site -- the cross-org
  warning added earlier on this branch (`tenant_resolver.go`) -- and the same
  shape was in eight more: the CSRF middleware's `origin`/`referer`/`path`, the
  request logger's `path`/`method`/`client_ip`/`user_agent`/`query_params`, the
  OPA middleware's `path`/`method`, the rate limiter's `key` (which embeds the
  client IP) and `path`, and `internal/common/logger`'s second request logger.
  All now go through `logsafe.String`. `request_body` deliberately does not: it
  is a payload rather than an identifier, `logsafe.MaxLen` would cut it to 256
  bytes and defeat the option somebody turned on, and it is already bounded at
  10 KB -- said in the code rather than left for a reader to wonder about.

- **The mandatory cross-org audit trail had never been written by a test, and
  could not have been where it was aimed.** `TestCrossOrgIsolation`'s
  platform-admin subtest skipped on every run of its life -- "admin is not a
  platform admin in this environment" -- so `audit.CrossOrgAuditor`, the row
  that makes a platform admin crossing a tenant boundary accountable, was
  asserted nowhere. That code is the kind that fails silently: a failed insert
  is logged and the request succeeds anyway, so a broken trail looks exactly
  like a working one. Chasing the skip found why it could never have passed:
  `TenantResolver` is mounted **before** route-level auth on identity-service
  and five other services, so at resolution time the context carries no roles,
  `SuperAdminPredicate` is false for every caller, and steps 2 and 3 of the
  resolver's documented precedence are unreachable there. `admin-api` mounts it
  on `/api/v1` after auth and is the one service where the control is live. The
  suite now proves both halves where they are true: X-Org-ID is inert on a
  service that resolves before auth; on admin-api a `super_admin` crosses and
  the audit row lands under the **target** org, a plain admin does not cross and
  no row is written, and the RLS bypass the insert depends on is shown
  load-bearing on a NOSUPERUSER connection (CI connects as a superuser, where
  RLS is ignored and the bypass would look unnecessary). admin-api now starts in
  the integration job alongside the other three. No migration seeds a
  `super_admin` role -- v134 grants a permission to one and matches nothing --
  so the fixture creates and removes it.

- **Nine tests that ran no code at all.** Seven in `internal/directory` over
  the directory authentication router, one named after a function it never
  called, one that read fields off a zero value it had built itself. Each was
  the shape `_ = service.AuthenticateUser` -- a method VALUE assigned to the
  blank identifier, which is not a call: the function under test never ran, and
  the only thing established (that the method exists) the compiler already
  guaranteed. The directory ones carried the comment "Without a real DB, we
  test the method signature exists" in a package that has had a testcontainers
  harness the whole time. `scripts/check-inert-tests.sh` could not see any of
  them -- it looks for an unconditional `t.Skip`, and these do not skip; they
  run and report a tick. New `tools/inerttests` (go/ast, so a method value and
  a method call are told apart exactly) fails the build on the shape, with an
  8-case self-test whose negative cases are the legitimate look-alikes it must
  not touch: a call assigned to `_`, a compile-time interface assertion, a real
  test that discards one result. All nine replaced with tests that run the
  code: the directory router's refusals (an Entra directory must not hand a
  password to the LDAP connector; an unknown type must not fall through to it;
  a disabled or other-tenant directory authenticates nobody), the sync-log
  reads' tenant scoping, `ListenAndServe` actually serving and releasing its
  port, and the org-lookup adapter narrowing a twelve-field `Organization` to
  the two-field value it puts on every request's context.

- **A second tenant could not name a role, a service account or a SCIM group
  the way the first one had.** `roles.name`, `service_accounts.name` and
  `scim_groups.display_name` were UNIQUE across the whole install while the rows
  were per-tenant: all three tables already carry `org_id NOT NULL` and FORCE
  ROW LEVEL SECURITY, and every query that reads them by name already names the
  organization. Only the key disagreed, and what it cost is a refusal rather
  than a leak -- the second organization to want a role called `developer` is
  told `duplicate key value violates unique constraint "roles_name_key"` about a
  row its own queries can never see. `developer` is not a corner case: the seed
  creates `admin`, `manager`, `user`, `auditor` and `developer` for the default
  organization on every install, so the five most ordinary role names are taken
  before the second tenant arrives, and a SCIM group named `Engineering`
  colliding across tenants is the ordinary case rather than the unlucky one --
  there the failure lands inside directory provisioning rather than in front of
  an operator. Migration **v173** re-keys all three to `(org_id, <name>)`, the
  same shape v138 gave `ispm_rules`, `ispm_scores` and `ai_agents`; no column is
  added and no belt changes, because all three tables already have both.
  `ziti_identities.name` and `ziti_services.name` are deliberately left
  install-wide: those names live in the Ziti controller, an install has one
  controller, and widening the local key would move the collision out of a clean
  database error and into a provisioning failure against the overlay.

- **Searching users returned a 500 on every call.** `ListUsers`'s search branch
  ends `ILIKE $1 ESCAPE '\\'`, written inside a Go **raw** string, so the SQL
  text carries two backslashes where Postgres allows exactly one character:
  `ERROR: invalid escape string ... Escape string must be empty or one
  character` (SQLSTATE 22025), on every search, on every install. The console's
  user-search box could never have worked. Both sites now send one backslash,
  and the escaping the clause exists for is asserted -- a search for `a_b` must
  not match `axb`.

- **One user with no first name broke the entire user list.** `users.first_name`
  and `last_name` are nullable and `UserDB` scans them into plain strings, so a
  single such row failed the whole call with "cannot scan NULL into *string" --
  not a bad row, a bad page. The product's own create path writes `""`, which is
  why it stayed hidden; a directory-synced user, a SCIM import or a row predating
  the column produces one. The three user SELECTs and the three WebAuthn lookups
  (where the same scan turned a passkey login into "user not found") now
  COALESCE both columns.

- **The DB-backed benchmark suite had never run, and could not have.** Sixteen
  benchmarks across `internal/identity` and `internal/oauth` pointed at a
  hardcoded DSN naming a database (`openidx_test`) that neither CI nor the
  compose stack creates, so they skipped everywhere -- and the benchmark job runs
  `go test -bench=. ./...` with no Postgres service at all. Underneath the skip:
  every id was a string like `bench_role_8f3a` fed to a `uuid` column, the
  seeding Execs discarded their errors, `ON CONFLICT (name)` named indexes that
  no longer exist, one insert named three columns `user_sessions` has never had,
  another seeded the wrong table entirely, and every timed call ran under a bare
  `context.Background()` so it returned "orgctx: no organization context" before
  touching the database. They now read `DATABASE_URL`, seed through valid
  statements under an org-scoped context, fail rather than continue when a
  fixture does not land, and check after the timed loop that the call they timed
  did not error on every iteration. `BenchmarkAuthenticate` reports ~80 ms/op
  now, which is bcrypt actually running; it used to report ~1 µs. The two user
  defects above are what running them turned up.

- **A resolver that could not answer looked exactly like one that answered
  "no".** `TenantResolver`'s documented precedence promises four steps, but
  steps 2 (JWT `org_id` claim) and 3 (platform-admin `X-Org-ID`) read the gin
  context, so they exist only where the middleware is mounted after the auth
  middleware that fills it. Six services mount it globally with `router.Use`,
  ahead of route-level auth; only `cmd/admin-api` mounts it on an authenticated
  group. On the six, every request silently lands on the default org whether the
  caller is a platform admin or not, and that stayed unnoticed for a release
  because both outcomes look identical from outside. The doc comment and all
  seven wiring sites now say which they are, and a new `Logger` field reports the
  mismatch -- once, at the moment a caller actually sends `X-Org-ID` to a
  resolver that cannot act on it. Deliberately narrow: a caller who simply is not
  a platform admin has roles in context and logs nothing, because a warning on
  ordinary refusals is one an operator filters out. Nothing about the resolution
  changes; the fail-safe direction was already right, it was just invisible.

- **The gateway's route table had no test, behind a reason that was untrue.**
  `TestRegisterServiceRoutes` skipped with "route conflicts in the routes
  package"; `registerServiceRoutes` registers 63 routes on a fresh engine
  without conflict, and has since the duplicate health registration moved out.
  It now asserts every proxied service is reachable by every method a REST
  client uses, that each proxied group resolves to a backend URL (and vice
  versa, so neither list can drift alone), that the docs endpoints are served,
  and that `/health` is **not** registered here -- registering it twice panics
  the gateway at boot, in production, which no test could previously catch.

- **Authorization-code expiry and single-use were both untested.** The expiry
  subtest was a bare skip ("requires code TTL modification or long wait"), and
  the one named for replay protection asserted that a login helper returned a
  token. Neither needed what it claimed: the code is available to the harness,
  and expiry is a column. An expired code is now shown to be refused as
  `invalid_grant` and removed from the table, and a replayed code is shown to
  mint nothing -- both verified by mutating `ConsumeAuthorizationCode` and
  watching them go red.

- **`scripts/check-inert-tests.sh` looked only at the first line of a body.**
  A skip preceded by comments -- which is where the reason for not writing the
  test gets parked -- slipped past it, and two inert tests sat green behind a
  paragraph the whole time the guard was in CI. Blank lines and comments no
  longer clear the finding; a statement still does.

- **A denied access request could be approved back to life.** `handleApproveRequest`
  read the request only to compare `requester_id` against the caller; it never
  looked at the request's **status**, and the pending-count that decides whether
  to fulfil counts rows marked `pending` while being blind to rows marked
  `denied`. On a request with two approvers where the first denied, the second's
  row was untouched: their approval drove the count to zero and the request was
  flipped from `denied` back to `approved` and **fulfilled** -- the role granted
  over the top of a recorded refusal, with both decisions in the audit trail and
  nothing to say one had overridden the other. A decided request (denied,
  cancelled or already approved) now answers `409` and grants nothing. Found by
  the first test ever written for the denial path.

- **Five of the seven OpenAPI specs were not YAML.** `28df9119` wrote the
  shared-responses block into a path item, on top of that operation's
  `parameters:` key, in `audit-service`, `governance-service`,
  `identity-service`, `oauth-service` and `provisioning-service`; a sixth,
  `access-service`, parsed but referred to a `ServerError` response it never
  defined. It shipped in v1.34.0. Nothing noticed because nothing in this
  repository ever parsed them -- `docs.yml` copies `api/openapi/*` into the
  published site verbatim, so the API reference for five services was being
  served a file no parser accepts. All seven now parse with every local `$ref`
  resolving, no operation lost, and `scripts/check-openapi-parses.sh` holds it.

- **Twenty-eight tests could not fail.** `internal/governance/request_test.go`
  was nine functions and fourteen subtests, every one a bare
  `t.Skip("DB mock not available")` -- named after `SubmitRequest` /
  `ApproveRequest` / `DenyRequest`, methods this service has never had, while
  the package carried a container-backed `setupTestDB` the whole time.
  `jit_test.go` skipped duration-bounds cases as needing "service init" over
  validation that runs before `RequestElevation` touches a database.
  `response_test.go` skipped four cases as needing "a real Redis client" in a
  package that has used miniredis since it was written, three of them named
  after methods that do not exist. And `TestJITRequestValidation` re-implemented
  the validation inside the test body and asserted its own copy -- a tautology
  that would stay green if `RequestElevation` dropped every check. All replaced
  with tests that drive the real code; `scripts/check-inert-tests.sh` fails on
  the shape.

- **Two database-backed test suites ran nowhere.** `ci.yml`'s unit matrix gives
  every package a live Postgres and exports it as `DATABASE_URL`; it does not
  set `OPENIDX_TEST_DATABASE_URL`, which is the developer escape hatch for a
  workstation with Postgres but no Docker daemon. `internal/oauth`'s SAML
  service-provider **tenant isolation** suite and the **v172** migration test
  (per-organization SET replay protection) read only that variable and skipped
  when it was unset -- so they skipped on every CI run, and on any workstation
  where nobody exported it by hand, while the job reported success. A skipped
  test displays as a pass. Both now prefer the variable and otherwise start a
  throwaway container, the way the other nine database-backed helpers already
  did. `scripts/check-test-reachability.sh` fails on the shape, and its
  self-test puts each of the two suites back into the form it was merged in and
  requires the guard to go red on both.

- **A dispatched release left the images unstamped.** `release.yml` already had
  a `workflow_dispatch` path, for environments that cannot push a tag ref at
  all -- a branch-scoped git credential answers HTTP 403 for `refs/tags/*`.
  That path published binaries, a GitHub Release, signed checksums and a signed
  Helm chart, and stopped there: the tag it creates is made under
  `GITHUB_TOKEN`, GitHub deliberately starts no workflow from a token-created
  push, so `docker.yml` never ran and the images kept only their `:sha` tag.
  The outcome looked like a full release and was a release whose version tags
  did not exist -- the failure `docker.yml`'s own retag job carries a comment
  against. `release.yml` now hands off to `docker.yml` on that path
  (`workflow_dispatch` being one of the two events `GITHUB_TOKEN` may still
  start), `docker.yml` accepts the version and stamps both spellings --
  `X.Y.Z` / `X.Y` / `X` and `vX.Y.Z` / `vX.Y` / `vX`, plus `stable` -- from
  either trigger. The un-prefixed three are not decoration: on a tag push
  `docker/metadata-action`'s `type=semver` publishes them and that matches a
  tag ref and nothing else, so stamping only the `v` form would have left a
  dispatched release complete-looking while the documented
  `docker pull ...:1.34.0` returned 404. `scripts/check-release-dispatch.sh` holds
  the two paths together in CI -- its self-test regresses `docker.yml` to the
  pushed-tags-only shape the repository actually had and requires the guard to
  go red.

## [1.34.0] - 2026-09-06

The project-readiness programme (PR #883). One organising defect class: **a
control that displays without enforcing is a lie** — extended, phase by phase,
to a spec that describes an eighth of a surface, a documented endpoint that
404s, and a "release" artifact signed with a debug key.

The programme closed with a full audit on one tree
(`docs/evidence/final-audit.md`): build, vet, 77 Go test packages, 1,181
console tests, the org-scope gate and 55 guard runs, all green — and two
defects, fixed below.

### Added

- **Tenant isolation on the nine ISPM/AI tables** (migration v138). `ispm_rules`,
  `ispm_findings`, `ispm_scores`, `ai_agents`, `ai_recommendations`,
  `bulk_operations`, `enrolled_agents` and `notification_digests` had no
  `org_id`: one tenant's "Scan" deleted every other tenant's open findings, and
  the posture score was neither one tenant's nor the install's. All now carry
  `org_id` under FORCE RLS, with the install-wide unique keys re-scoped and an
  isolation test per handler file.
- **Cancelling a bulk account operation did nothing, and one organization's bulk
  runs were visible to every other** (migration v161). A bulk operation is the
  console's "do this to these fifty accounts" control — enable, disable, delete,
  add or remove a role or a group, force a password change.

  **Pressing Cancel on a running operation stopped nothing.** Cancel marked the
  operation cancelled in the database, and the code doing the work never looked
  at that mark: it worked through every account it had been given, and then
  recorded the operation as "completed", erasing the cancellation. So an
  administrator who realised mid-run that they were deleting the wrong fifty
  accounts could press Cancel, watch the screen say it was cancelled, and have
  every one of those accounts deleted anyway with the record showing a normal
  completion. Cancel now stops the run before the next account, and a cancelled
  run stays cancelled.

  **An operation that changed nothing reported success.** Every action was
  correctly limited to the caller's own organization, so naming an account from
  another organization changed nothing — and, because that is not an error in
  the database, each such account was recorded as a success. A run over fifty
  accounts that belonged to someone else reported fifty successes. Each is now
  recorded as a failure, with the reason.

  The runs themselves had no organization: the list showed every organization's
  operations, including what each one did and which role or group it applied,
  and opening one returned its per-account detail — **which is a list of
  usernames** — so one administrator could read another organization's
  directory through it. Cancelling addressed a run by identifier alone, so one
  organization could cancel another's import mid-flight. All of that is now
  scoped to the organization that started the run.

  Also fixed: the per-account detail list dropped any row it could not fully
  read, and the field it stumbled on is empty for every account that succeeded —
  so a run that worked appeared to have done nothing at all.

  **Operators of installations with more than one organization should note**
  that existing runs are assigned to the organization of whoever started them,
  and their per-account records follow the run.
- **Anyone signed in could end someone else's supervised session.** A privileged
  session on a connection that requires supervision cannot start until a second
  person joins to watch it. Ending that supervision also ends the session
  itself — it is the supervisor's stop button.

  The endpoint that does this is documented as being for the person being
  supervised or the person supervising, and it checked neither. **Any signed-in
  member of the organization could end any supervised session by naming it.**
  The effect is to cut a session short rather than to gain access to one, so
  this cost availability rather than granting anything — but it is a restriction
  the product described and did not apply. It now checks, and administrators
  keep the ability to clear a stuck session.

  The three screens behind this feature also resolved which organization the
  caller belonged to, refused anyone without one, and then did not use it. The
  database's own isolation rule was confining them regardless; they now say so
  themselves.
- **The credential vault's permission checks now name the organization
  themselves.** Whether somebody may reveal a stored credential, who may see the
  record of past reveals, and which permissions may be withdrawn were all
  decided by queries that relied on the database's own isolation rule rather
  than saying so in the query.

  On an ordinary request that is enough. But the vault has one path — the one
  that injects a credential into a remote session on the product's own behalf —
  that deliberately steps outside the boundary, and there the database rule is
  switched off and only what the query says is left. Those five checks now say
  it, and a test exercises them **in that condition** rather than the ordinary
  one. No exposure is known to have followed from this; it removes the
  dependence.
- **A cloud broker credential belonging to one organization could be spent by
  another.** The cloud just-in-time endpoint (`POST /pam/connect/cloud`) takes
  the id of a vault secret to authenticate with. It carried no administrator
  requirement, and the id was used exactly as sent: the endpoint established
  which organization the caller belonged to, refused anyone without one, and
  then never applied it to the credential it fetched. That fetch is the
  product's internal credential-injection path, which by design steps outside
  the database's tenant rule — so nothing else was scoping it either.
  Any signed-in user could therefore name another organization's AWS broker
  credential, have it used to assume a role of their own choosing, and receive
  working temporary cloud credentials in the response. The session was recorded
  against the caller's organization, so the organization whose credential was
  spent had no record of it.
  The credential fetch now requires the organization to be named explicitly and
  refuses to decrypt anything belonging to another one. Every caller passes it,
  and roughly twenty further vault and rotation queries across four packages now
  name the organization as well.
- **The log of security events received from a federated provider now records
  which organization each was applied to** (migration v172). When an upstream
  identity provider pushes a security event — a session revoked, an account
  disabled, a credential changed — OpenIDX applies it and writes a row so a
  re-delivery of the same event is not applied twice. Applying the event has
  always been confined to one organization. Recording it was not: the column
  meant to hold the organization existed and nothing ever filled it, so the log
  could not say whose event any row was. The de-duplication key was
  installation-wide for the same reason, which on a multi-tenant installation
  meant a second organization receiving the same event id would apply it and
  then fail to record it, losing its protection against a repeat. Both now name
  the organization, and a failure to write the record is logged rather than
  discarded — that row is the protection.
- **The approval that clears an AI agent's tool call to run now names the
  tenant that granted it.** Sensitive tools reached through the MCP gateway wait
  for a person to approve them. The check that asked *does this tool need
  approval* said which organization it was asking about; the check on the very
  next line — *has this call been approved* — did not, and that is the one that
  lets the call through. The approve/deny endpoint had the same shape: it
  resolved the administrator's organization, refused when there was none, and
  then decided an approval by the id in the URL without using it. The database's
  own tenant rule was scoping both, so no call was ever cleared by another
  tenant's approval; the checks now say so themselves, and hold when a caller
  steps outside that rule.
- **An access-certification item could be delegated to a reviewer in another
  organization, and then never decided.** The Attestation surface lets an
  administrator hand a certification item to a different reviewer. The user id
  in that request was written onto the item with no validation at all — not
  that it named a user, not that the user was enabled, not that the user
  belonged to the administrator's own organization. Row-level security did not
  stand in the way: it constrains which *rows* a tenant may touch, and this is a
  *value* written into a row the tenant already owns.
  A reviewer in another organization cannot see the item — reviewer names are
  read through an organization-scoped join, so it simply renders blank — so
  nothing was disclosed. What was lost is the certification: the item stays
  pending for ever, and a campaign completes only when its pending count reaches
  zero, so a single delegation froze the campaign permanently. `delegate_to`
  must now name an enabled user of the administrator's organization, which is
  the rule the product already applied to reviewers it assigned itself.
  Every one of the twenty-eight attestation statements also names the tenant
  now, and a campaign whose description is empty no longer drops silently out of
  the list it belongs to.
- **The approval request raised when an untrusted device is refused had never
  once been raised** (migration v171). When a device that has not been marked
  trusted reaches a resource protected by a device check, the product refuses it
  and — in its own words — "files a pending device-trust request so an admin can
  approve it". An administrator is meant to see that request on the Device Trust
  Approval screen and let the person in.

  An earlier migration gave those records a required organization column. The
  step that writes them was never updated to fill it, so **every attempt failed
  at the database and the failure was written to the log and discarded** —
  deliberately, because that step is best-effort and must never block the
  request it is refusing. The result: the check refused the device, said it was
  raising a request, and raised nothing. On every installation, for as long as
  that column has existed. A person locked out by a device check waited for an
  approval that was never in anybody's queue.

  The equivalent step on the self-service side always filled the column
  correctly; this was its counterpart. The organization now comes from the
  already-signed-in person, which is exact.

  A test did assert that the request was filed. It built its own copy of the
  table **without** the required column — a shape the product has not had since
  that migration — so it passed against a constraint that was not there. It now
  matches the real schema.

  Also in this change: report exports, agent enrolment sessions and these
  device-trust requests are all brought under the database's own isolation rule,
  which completes that work — every record type in the product that names an
  organization is now confined by the database as well as by the application.
  Two supporting fixes went with it: the background job that writes a finished
  report's status now carries the organization it is working for (without it the
  export would have stayed at "generating" for ever, with the file on disk), and
  the public endpoint an agent uses to redeem its enrolment code now says
  explicitly that it works across organizations, since it runs before any
  organization can be known.
- **A record that names the organization had never had one written into it**
  (migration v170). When an application registers itself with OpenIDX
  automatically — the standard mechanism for a client to sign itself up — it is
  handed a management credential so it can read, update or remove its own
  registration afterwards. The record holding that credential has had a column
  for the owning organization since it was created, and nothing had ever put a
  value in it. Every one of those records, on every installation, named no
  organization at all.

  That mattered because the plan was to bring this record under the database's
  own isolation rule. Doing that first would have made every one of them
  invisible, and every management call — read, update, remove — would have
  answered **"invalid registration credential"** for every application on every
  installation, with a perfectly valid credential in hand. The column is now
  filled from the application it belongs to, and only then enforced.

  A record whose application no longer exists is removed rather than assigned to
  someone: it could never be used again, and filing another organization's dead
  credential under theirs would be worse than deleting it.

  **This was not an exposure.** The lookups involved use the application's
  identifier, which is unique across the whole installation, and both management
  screens read the application itself — already confined to its organization —
  immediately afterwards, so a caller from elsewhere was already refused there.
  What changes is that these lookups no longer depend on a property of a
  different record, and keep working for maintenance jobs that deliberately
  range across organizations.

  Also brought under the same rule: the codes used when signing in on a device
  that has no keyboard (a TV, a console). Their organization was already
  recorded and every lookup already used it; the four follow-up updates that
  addressed a code by its row now name it too.
- **The system-health repair tool required no administrator role** (migration
  v169). The Relations & Integrity Doctor on the System Health page finds
  inconsistencies across the whole installation — an application whose network
  service no longer exists, two applications claiming the same address — and
  offers to repair them. It is deliberately install-wide: it deliberately steps
  outside the per-organization boundary so that an operator can see the whole
  picture.

  **Its two endpoints required only that the caller be signed in.** Every
  neighbouring administrative endpoint requires an administrator; these did not,
  and because they deliberately step outside the organization boundary, nothing
  else was confining them either. Any signed-in user of any organization could:

  - read a report naming every organization's published applications, their
    public addresses, their sign-in client identifiers and their network service
    names;
  - apply every repair marked safe, across every organization, in one request;
  - apply one of the two repairs the product itself marks risky — removing a
    service from the network controller, or consolidating an application, which
    rewrites another organization's routes and re-points their discovered paths.

  Both endpoints now require an administrator, and a test drives the product's
  real routing table to prove it, so a route added here in future cannot quietly
  skip the check.

  Also in this change: the App Publish records (published applications and their
  discovered paths) are brought under the database's own isolation rule. Their
  earlier migration had recorded a reason for leaving them out — half of it had
  since stopped being true, and the other half needed one line so that the
  background path-discovery job carries the organization it is working for.
  Changing the classification of a path — which decides whether it is published,
  behind what sign-in, and under what device requirement — now has a test
  covering the cross-organization case it did not have.
- **One organization could add a permission to another organization's AI tool
  gateway** (migration v168). The MCP gateway lets an administrator register an
  upstream an AI agent may be proxied to, and then list which callers may use
  which tools on it. That list is an allowlist: a line on it grants permission,
  and nothing else decides the question.

  Adding a line took the upstream's identifier from the address bar and **never
  checked the upstream belonged to the administrator's organization**. So an
  administrator of one organization could name another's upstream and add a line
  to it. The line names a role — and role names are not unique across
  organizations, so a line granting "analyst" was then applied to *that*
  organization's analysts, on *their* upstream, and appeared on their own policy
  page as though one of their administrators had written it.

  Everything around it was already confined correctly: listing, opening and
  deleting an upstream all checked the organization. The upstream was protected
  and the permission attached to it was not.

  Fixed in the same change: the tool-permission check, the approval-requirement
  check and the pending-approvals list now each carry the organization; four
  places where an empty organization was treated as *every* organization are
  gone; registering an upstream or adding a permission without an organization
  is refused rather than silently writing a record no one can see afterwards;
  and the four screens behind this now answer "forbidden" instead of running
  with no organization at all. Both record types are also brought under the
  database's own isolation rule.

  **Operators of installations with more than one organization should note**
  that existing records are assigned to the organization that owns them, and any
  record stored without one is attributed to the primary organization — worth a
  look at the tool permission list on each gateway after upgrading.
- **Group-to-application assignments were protected by a rule the database did
  not apply to every connection** (migration v167). When an application is
  assigned to a group, that record decides who may reach the application. It was
  given a database rule confining it to its own organization, but not the second
  setting that makes the rule apply to the account that owns the tables as well
  as to everyone else.

  On the deployment this project documents, migrations and the running services
  connect as different database accounts, so the rule applied and the records
  were confined — **this was not an exposure there**. On an installation where
  the two are the same account (a single-account database, a hosted service
  whose application user owns the schema, a developer's machine), the rule did
  not apply to the application at all, and this record was protected only by the
  product's own filtering. Every comparable record — direct user assignments,
  group memberships, the applications themselves — already had both settings.
  This one now does too.

  A check was added that asks the database directly whether every record type
  with such a rule also has the second setting, so a future migration cannot
  omit it quietly. Run against the previous schema it identified this record
  type and no other.
- **Revoking someone's network access reported success even when the
  disconnection failed** (migration v166). When an access review revokes access,
  or a time-limited grant expires, the product records the decision and then
  hands the actual work — removing the network permission and cutting the user's
  live connections — to a background worker.

  **The worker marked every item done regardless of whether it had worked.** If
  the network controller was unreachable, or the call to sever the connection
  failed, the failure was written to the log and the item was recorded as
  completed anyway. The reviewer saw a revocation; the user's live connection
  stayed open; every record agreed it had been cut. The worker now records a
  failure as a failure.

  **A failed hand-off was retried never and read by nobody.** Both queues have
  had an attempt counter since they were created and neither worker ever used
  it, so one transient controller error lost the change permanently — a granted
  request whose permission was never applied, or a revocation that never
  happened. And nothing in the product reads the failure state, so there was no
  screen, alert or report where it appeared. Failures are now retried, and a
  hand-off that exhausts its retries is written to the audit trail of the
  organization it belongs to, where it can be seen.

  Both queues also gain database-level protection and can no longer be stored
  without an organization. The background worker is unaffected: it is
  deliberately installation-wide and already had an explicit exemption.
- **A device reported by one organization's endpoint-security connection could
  cut off another organization's user** (migration v165). OpenIDX can read
  device compliance from CrowdStrike, Intune, Jamf or Wazuh and use it as a
  posture signal: a device the security tool reports as non-compliant fails its
  posture check, and that is what revokes the session and disconnects the
  device from the private network.

  **The step that decides *whose* device it is looked across all
  organizations.** A reported device is matched to a local identity by email
  address, hostname or serial number, and that lookup named no organization —
  so a device reported by one organization's connection could be matched to a
  user in another, and which one was decided by the database's own query plan.
  The effect was a disconnection, not a disclosure: one organization's security
  tool calling a laptop non-compliant could cut off someone else's user, on
  nothing more than a shared email address — which is the ordinary case for one
  person employed by two organizations on the same installation. The match is
  now confined to the organization that owns the connection.

  The connections themselves also gain database-level protection, which the
  migration that created them said they had and never applied, and their
  organization can no longer be left empty. As with the outbound provisioning
  connections above, the "empty organization means all organizations" shortcut
  in the queries is gone, and these endpoints now refuse a request that arrives
  without an organization. The background poller that reads the security tools
  is unaffected: it is deliberately installation-wide and already had an
  explicit exemption.

  **Operators of installations with more than one organization should note**
  that device records follow their connection exactly, but a connection stored
  with no organization is assigned to the oldest one — and the next poll writes
  posture results, so check which connection belongs to whom first.
- **Outbound provisioning connections were not protected by the database, and
  their organization could be left empty** (migration v164). These are the
  connections that push your users out to Slack, Okta, Entra and similar: a base
  URL, an encrypted administrative credential, and a queue of pending changes.

  Their records carried an organization, but the database was never told to
  enforce it — the migration that created them says it made them
  "org-scoped for RLS" and that protection was never applied. Every query
  relied on the application remembering to filter. It now relies on the
  database, which refuses to return another organization's rows regardless.

  **The organization could be empty, and an empty organization meant all of
  them.** The column allowed no value at all, and every "scoped" query treated
  an empty organization as a wildcard. Reached that way, the list returned every
  organization's provisioning connections, delete removed any of them along with
  their history and pending queue, and a full sync would have pushed the entire
  installation's directory — every username, email and name — into one
  organization's downstream service.

  **This was not reachable in a running deployment**, and we would rather say
  so than imply otherwise: the provisioning service resolves the organization
  for every request before any of these endpoints run, and rejects the request
  when it cannot. The wildcard was one configuration change away from mattering,
  and it contradicted the database protection being added — so it is gone, and
  the endpoints now refuse a request that arrives without an organization
  instead of treating it as every organization. A connection can no longer be
  stored without one either.

  The background worker that delivers queued changes is unaffected: it is
  deliberately installation-wide, and already ran with an explicit exemption.

  **Operators of installations with more than one organization should note**
  that pending changes and delivery history follow their connection exactly, but
  a connection that was stored with no organization is assigned to the oldest
  one. If you have more than one organization, check which connection belongs to
  whom before the next sync runs.
- **One organization could reclassify another's roles, and the button that saves
  a classification had never worked** (migration v163).

  The Entitlement Catalog lets an administrator annotate a role, a group or an
  application: its risk level, its owner, its tags, and whether it requires
  review. Those annotations had no organization, and the identifier they were
  stored under was unique across the whole installation — so an administrator
  who knew another organization's role identifier could set that role's risk
  level, name an account of their own as its owner, retag it, and switch its
  "review required" badge off. The change appeared on the other organization's
  catalog. Annotations are now the annotating organization's own, and naming an
  entitlement or an owner from outside it is refused.

  **The Save button had never worked at all.** The statement that stores an
  annotation put a text value into a column that holds an identifier, which the
  database rejects before it runs — for every request, whatever was being saved.
  So every Save on the Entitlement Catalog has returned "internal server error"
  since the feature shipped. Fixed.

  **The risk breakdown could show a negative number.** The catalog's summary
  counted this organization's roles, groups and applications, then subtracted a
  count of annotations taken from the entire installation. Where another
  organization had annotated more entitlements than this one owns, the "low
  risk" figure came out below zero — a count of things, printed negative, beside
  figures that were correct. Both halves are now this organization's.

  **Notification digests** are also now scoped to the organization, though they
  were never reachable across organizations: each request only ever read the
  calling user's own row. Worth stating plainly for anyone relying on the
  feature: **nothing sends a digest.** The schedule is stored and no part of the
  product reads it, so choosing a daily or weekly digest in Notification Center
  has never resulted in one being sent. That remains outstanding work; this
  release does not change it.

  Two unused tables were removed: one that nothing had ever written to and whose
  only reader asked it for two columns it does not have, and one referenced
  nowhere in the product at all. The Feature Adoption analytics page is
  unaffected — it has always computed its figures live, because the read of the
  stored table failed silently every time.

  **Operators of installations with more than one organization should note**
  that existing annotations are assigned to the organization that owns the
  entitlement they annotate, which is exact, and existing digest settings to the
  organization of the user they belong to.
- **One organization could switch off another's private-network protection for
  an application, and read their internal server names** (migration v162). Two
  records had no organization: the per-application feature switches (whether
  private-network access, browser-based access or remote-desktop brokering is on
  for a route) and the results of the "Test connection" button.

  **The switch was protected in one direction only.** Turning a feature *on* for
  an application belonging to another organization was already refused. Turning
  one *off* was not checked at all, so an administrator who knew an
  application's identifier could switch off another organization's
  private-network protection for it — and, on installations that provision
  directly rather than through the reconciler, the underlying network service
  was deleted outright. The owning organization's console went on showing the
  application as protected, because the one statement that would have updated
  that display *was* limited to the caller's own organization and so changed
  nothing. Both directions are now checked.

  **The connection-test history named internal hosts.** Each stored test result
  holds the application's upstream address, the host and port a connectivity
  probe dialled, the private-network service name, and the raw error text of a
  failed connection — which names the server it could not reach. That history
  was read by application identifier with no organization attached, so it was
  readable across organizations, and by a caller with no organization at all.
  Both the test and its history now require one and return only the caller's own.

  **The health indicator beside each feature was never written.** The coloured
  dot on the Zero Trust page and the badge on an application's feature panel
  read from a field nothing in the product ever set, so they have shown
  "unknown" for every feature on every application since the field was
  introduced. The connection test already measures exactly what they report —
  it resolves the private-network service and validates the remote-desktop
  connection — and now records its verdict, so the indicator means "the last
  connection test said this". It stays "unknown" until a test has run, and a
  test that did not probe a feature leaves that feature's indicator alone.

  **Operators of installations with more than one organization should note**
  that existing feature switches and test results are assigned to the
  organization that owns the application they belong to, which is exact.
- **One set of email templates for the whole installation, and an announcement
  another organization could send** (migration v160). Three records had no
  organization: the email templates, the notification routing rules, and the
  broadcast messages.

  Every administrator on the installation saw and could rewrite **one shared set
  of email templates** — the subject line and body of the mail the product sends
  about passwords, invitations, verification and one-time codes — and template
  names were unique across the installation, so the first organization to create
  a template called "welcome" owned that name for everyone and the next
  organization's attempt failed with an unexplained error. Each organization now
  has its own templates and its own names.

  A **broadcast** is an announcement an administrator sends to their users. The
  send endpoint worked out the recipients from the caller's organization but
  loaded the announcement itself by identifier alone, so an administrator could
  take another organization's unsent draft and deliver it, as their own, to
  their own people. Reading, listing and deleting a draft were unscoped
  outright. And a **notification routing rule** decides which channels an event
  reaches, so one organization could switch another's security-alert rule from
  in-app-and-email to in-app only, and those alerts would stop arriving by mail
  with nothing on screen to say so. All three now carry the organization.

  **Operators of installations with more than one organization should review
  their email templates and routing rules after upgrading.** Records are
  assigned to the organization of whoever last edited them; the five starter
  templates the product ships carry no editor, so they go to the oldest
  organization and other organizations start with none.

  Also fixed: an email template saved without a plain-text body disappeared from
  the template list entirely — the list dropped any record it could not read and
  said nothing. Also recorded, and not yet fixed: nothing in the product sends
  these templates. No mail the product delivers reads one, by name or otherwise,
  so the template editor has always saved copy that nothing uses. Wiring the
  mailer to them is outstanding work.
- **Any administrator could read, disable or delete another organization's
  device lockdown policies, and aim one at a device** (migration v159). A kiosk
  policy puts a managed device into locked-down mode: which apps may run, which
  screen is pinned, the branding shown, and the PIN required to leave. The
  records had no organization. The administrative list returned every policy on
  the installation — its own code comment said so — and reading, editing and
  deleting a policy needed only its identifier, so one organization's
  administrator could turn off another's device lockdown with nothing on the
  owning console to say the control had stopped existing.

  Assigning a policy to a device was worse: the endpoint took the policy from
  the address and the device from the request body and checked neither, so an
  administrator could aim another organization's lockdown — and its exit PIN —
  at a device. Policies, assignments and every one of the eight endpoints now
  carry the organization, and assignment verifies the policy belongs to the
  caller.

  **What this does not settle**, stated plainly: enrolled agents have no
  organization, by an existing deliberate decision. So an agent identifier names
  a device without naming a tenant, and while an administrator can no longer aim
  *another organization's* policy at a device, nothing yet stops them aiming
  *their own* policy at a device someone else enrolled. Whether the agent fleet
  should be per-organization is an open product decision.

  **Operators of installations with more than one organization should review
  their kiosk policies and assignments after upgrading.** Existing policies are
  assigned to the organization of whoever created them, and assignments follow
  their policy; anything unattributed goes to the oldest organization.

  Two more, alongside. Creating a kiosk policy without specifying the allowed
  apps, the lock-task features or the branding — all three optional — failed
  with an unexplained server error; it now works, using the defaults the schema
  already declared. And two tables this release removes, `policy_recommendations`
  and `compliance_gaps`: they were created for an AI policy-suggestion endpoint
  that was itself removed as dead earlier in this programme, and nothing in the
  product has read or written either since.
- **One organization's biometric rule could decide another organization's
  sign-in, and which rule won was decided alphabetically** (migration v158). A
  biometric policy says which authenticator types are allowed, whether a
  built-in authenticator (Face ID, Touch ID) is required, and which groups and
  roles the rule covers. The record had no organization, and the code that finds
  the rule for a user listed every rule on the installation, sorted them by
  name, and took the first one that applied — where a rule naming no groups and
  no roles applies to everyone. So any administrator anywhere could create an
  untargeted rule that governed every user on the installation, and the winner
  was whoever chose the earlier name. It could weaken as well as tighten: the
  default rule allows both authenticator types, so a permissive rule sorting
  first replaced a restrictive one and the check meant to refuse a roaming
  security key accepted it. Rules are now per organization.

  Administrators could also see, edit and delete each other's rules across
  organizations — the list returned every organization's, including the group
  identifiers and role names each rule targets — and a user's own biometric
  preferences, including whether their account is sign-in-by-biometric-only and
  whether the authenticator must verify the person, were readable and writable
  by user identifier alone. All of those now carry the organization.

  **Operators of installations with more than one organization should review
  their biometric policies after upgrading.** Existing rules are assigned to the
  oldest organization, because the records carry no information about who
  created them; any other organization relying on a rule it did not author must
  create its own.

  Two more, found alongside. The passwordless settings page divided a count of
  biometric-only accounts across the whole installation by a count of users in
  one organization, so a small organization sharing an installation with a large
  one saw a biometric adoption rate above 100%. And reading a user's biometric
  preferences answered any failure — a database error, a permission problem —
  with the built-in defaults and no error at all, which is indistinguishable
  from "this person has not chosen any"; a failure is now reported as a failure.

  Also recorded, and not yet fixed: nothing in the product consults a biometric
  policy. No registration path and no sign-in path checks one, so the policy
  page has always saved rules and constrained no enrolment. Giving those rules
  an enforcement point is outstanding work rather than something this release
  delivers.
- **One password policy, one MFA requirement and one set of allowed sign-up
  domains for the whole installation; and a continuous-authentication engine
  that had never once run** (migration v157). The admin console's settings page
  saves four records — general, security, authentication and branding. Their key
  was the table's primary key, so there were four records on the installation in
  total and every organization's administrators shared them. The security record
  holds the password policy (minimum length, required character classes,
  forbidden words, maximum age, history depth), whether multi-factor
  authentication is required and which methods are allowed, and the session
  timeouts; the authentication record holds the email domains allowed to
  register. One administrator lowering their minimum password length, or
  switching MFA-required off, did it for every organization — and each
  organization's page showed them whatever had been saved last, by anyone.

  This is not only a display problem. The password checker
  (`POST /api/v1/settings/validate-password`) reads that same shared security
  record, so the policy a password was measured against was whichever one had
  been saved most recently, by an administrator of any organization. Each
  organization now has its own four records, and its own policy.

  **Operators of installations with more than one organization should review
  their console settings after upgrading.** The existing records are assigned to
  the organization of whoever last saved them; every other organization starts
  from the built-in defaults, which are the stricter setting in each case, and
  should save its own.

  Separately, the continuous-authentication engine — which scores a live session
  for risk and can require a step-up or end the session — read its session
  information from a table that no part of the product has ever written a row
  to. Its three endpoints have therefore only ever returned an error, and its
  "record a risk event" endpoint reported success while storing nothing. The
  engine now reads the session and risk-history tables the product actually
  writes, under the caller's organization, so one organization can no longer
  score or end another's session. Three faults that this uncovered are fixed
  with it: two of the three endpoints graded every session "critical" because
  their thresholds were left at zero, an unrecognised event name was silently
  scored as nothing and reported as recorded, and the detail supplied with an
  event was discarded.

  Also recorded, and not yet fixed: the engine's device factor needs a device
  fingerprint, and nothing records one against a session. Rather than treat
  every session as an unrecognised device — a fixed number presented as a
  measurement — that factor now reports itself unavailable, and the response
  says which factors the score was actually built from. Recording a fingerprint
  at sign-in is outstanding work.
- **The developer portal kept one settings record for the whole installation,
  and its OAuth playground handed out a live flow's secret to anyone who knew
  the session's identifier** (migration v156). The developer settings page sets
  the maximum number of API keys a user may hold, which permissions an API key
  may carry, the webhook address allowlist, the browser origins allowed to call
  the API, the default rate limit, and whether sandbox mode is on. There was
  exactly one such record on the installation, shared by every organization:
  whichever administrator saved last chose all of it for everyone. Each
  organization now has its own.

  The console's OAuth playground — the tool for stepping through a sign-in flow
  by hand — stores the secret that lets that flow's authorization code be
  exchanged for a token. It was retrievable by session identifier alone: no
  check of which organization the session belonged to, no check that the person
  asking was the one who started it, and, unlike every other page in that part
  of the API, no check that they were an administrator at all. All three checks
  are now in place.

  **Operators of installations with more than one organization should review
  their developer settings after upgrading.** The existing record is assigned to
  the organization of whoever last saved it; every other organization starts
  from the defaults and should set its own.

  Also recorded, and not yet fixed: none of the developer settings is consulted
  by anything. No API-key issuance checks the maximum or the permitted
  permissions, no browser-origin check reads the allowlist, no limiter reads the
  rate limit. The page has always saved six limits and enforced none of them,
  which is why sharing the record between organizations has not caused visible
  harm. Making those values take effect is outstanding work rather than
  something this release delivers.
- **Every organization's single sign-on routing was visible to every
  administrator, and two organizations could not share a domain or an identity
  provider** (migration v155). A federation rule says which identity provider
  authenticates a given email domain — the record that decides where someone
  typing their work address is sent to sign in.

  The administrative list of those rules showed every organization's, not just
  the viewer's. The check that was meant to confine it sat in a part of the
  query that decides how to *label* a row rather than whether to *return* it,
  so it filtered nothing and merely left the provider name blank on the rules
  belonging to other organizations. Rules could also be edited or deleted by
  anyone who knew their identifier: an administrator elsewhere on the
  installation could switch off another organization's SSO for a domain, after
  which its users would quietly get a password prompt instead, with nothing on
  the owner's screen to say the routing had changed. And a rule could be
  created naming an identity provider belonging to a different organization.
  All of this is now confined to the organization that owns the rule, and a
  rule can only name a provider from that same organization.

  Two limits that made multi-organization installs impossible are lifted in the
  same change. An email domain could be registered **once per installation**:
  whoever claimed it first held it everywhere, and the next organization to try
  got an unexplained failure. An identity provider's issuer address was
  likewise unique installation-wide, so two organizations could not both
  federate to the same provider — two departments on one corporate tenant, or
  simply both using the same public provider. Each is now unique per
  organization, and a duplicate within one organization gets a message saying
  so rather than a generic error.

  **Operators of installations with more than one organization should review
  their federation rules after upgrading.** Each rule is assigned to the
  organization of the identity provider it routes to. A rule every
  administrator could see will now be visible to one.

  Also recorded, and not yet fixed: the custom claim mappings configured per
  application — "include the user's department in the token as `dept`" — are
  saved, listed back, and read by nothing. No token has ever carried them. The
  page's three destination switches (ID token, access token, userinfo) have no
  consumer behind them. The mappings are now confined to the organization that
  owns the application, so they can no longer be added to or removed from
  another organization's applications, but making them actually reach a token
  is outstanding work rather than something this release delivers.
- **A second organization could re-aim the rule that disables and deletes
  accounts** (migration v154). Joiner/mover/leaver automation is two kinds of
  rule — a workflow that runs on a person's arrival or departure, and a
  de-provisioning policy that sweeps for stale, disabled or orphaned accounts —
  plus a log of what each run did. Between them the actions available are: add
  or remove a role, add or remove a group membership, revoke every session,
  force a password change, disable the account, and delete the account.

  Everything those rules **do** was already confined to the organization the
  rule was run in. What the rules **were** belonged to nobody. Any
  administrator could list every organization's rules, open one, and change
  both what it looks for and what it does. A policy named "Stale Account
  Auto-Disable — 90 days" could be turned into "delete anything idle for zero
  days", which is every account, and handed back unchanged in name. Its owner
  then runs the rule they have always run, on their own directory, and the
  confinement of the action is no help at all: the accounts destroyed are
  theirs. The same reach allowed deleting another organization's offboarding
  rule outright — after which nothing on their console says the control that
  used to disable departing staff has stopped existing.

  The run logs were readable across organizations too, and they are not
  status: each entry names every account the run touched, the action taken
  against it, and the reason it was selected.

  All four record types now belong to an organization, and every listing,
  view, edit, deletion and run is limited to the caller's own.

  **Operators of installations with more than one organization should review
  their lifecycle rules after upgrading.** Rules are assigned to the
  organization of whoever created them; run logs follow the account they acted
  on; anything the upgrade cannot attribute goes to the oldest organization. A
  rule that every administrator could see will now be visible to one. If a
  second organization had been relying on a rule the first authored — which it
  was never entitled to — it needs its own.

  Fixed alongside it: a completed policy run was invisible in its own history.
  The run record leaves the error field empty when nothing went wrong, and the
  reader could not cope with an empty value, so it skipped the row silently —
  an administrator opening the history of a policy that had just disabled fifty
  accounts saw an empty list. The same fault could hide a whole rule from the
  policy list. Both readers now handle the empty values, and a skipped row is
  logged instead of disappearing. And running a workflow against an account in
  another organization is now refused outright rather than recorded as
  completed work that never happened.
- **One organization's sign-in rule could weaken the second factor for every
  organization** (migration v153). A risk policy is a rule the sign-in path
  consults: when this condition holds, ask for a second factor, ask for a
  stronger one, refuse the sign-in, or accept these particular factors. The
  rules carried nothing saying which organization they belonged to, and the
  sign-in path read all of them and applied every one that matched.

  The damaging direction is the permissive one. When a sign-in looks risky the
  system narrows the acceptable second factors to the two that resist phishing
  — a security key or a push approval. A rule that names acceptable factors
  does not add to that list, it **replaces** it. So a rule created in one
  organization saying "any factor is acceptable" put one-time codes by SMS and
  email back into every other organization's high-risk sign-ins. The condition
  needed to trigger it is not exotic either: "risk score at least 0" is true of
  every sign-in there has ever been. The same rule with "refuse" instead would
  have blocked every sign-in on the installation.

  Rules are now owned by an organization and only that organization's rules are
  consulted, read or written. Listing, viewing, editing, enabling and deleting
  are all limited to the caller's own.

  **Operators of installations with more than one organization should review
  their risk policies after upgrading.** These rules had no owner, so the
  upgrade assigns every existing one to the oldest organization — there is no
  other information on the record to go by. A rule that had been applying
  everywhere will now apply in one place. That is the intended direction, since
  no organization was ever meant to have another's rule applied to its
  sign-ins, but the rules you meant each organization to have will need
  re-creating there.

  Fixed alongside it: one rule with an empty description made the sign-in path
  fail to load **any** rules at all, on every sign-in, for the whole
  installation. It failed in the safe direction — the path falls back to asking
  for a second factor — but every refusal, every step-up and every factor
  restriction an administrator had configured was silently doing nothing. The
  same table is read elsewhere in the product with the empty value handled
  properly; this reader had never had it.
- **A delegated administrative permission followed the person into other
  organizations, and the permission cache shared it with their colleagues**
  (migration v152). A delegation record grants one person a named set of
  administrative powers — "may reveal stored credentials, until this date." It
  is read by the component that decides whether a request is allowed, and
  merged into that person's permissions for the request. The record carried
  nothing saying which organization it belonged to.

  Two lookups sit side by side in that component, and both run with the
  database's own restrictions deliberately lifted, because at that point in a
  request the organization has not yet been established and a restricted read
  would return nothing and refuse everybody. The first lookup limits itself to
  the caller's organization and its note says so. The second, added later, says
  it uses the same reasoning — but limits itself to the person, not the
  organization. So it did not limit itself at all: a delegation granted in one
  organization applied to that person wherever else they could act.

  The cache made it worse in a different direction. Permissions are cached for
  five minutes under a key made of the organization and the person's roles, and
  the delegation lookup was adding its own caller's personal grants to what got
  stored. Every other person in that organization holding the same roles was
  then served one individual's delegated powers as their own, for as long as
  the entry lived, and again on the next miss. Personal grants no longer go
  into a shared entry: the expensive role lookup is still cached, the
  delegation lookup runs per request, and entries written by the old code are
  no longer read.

  The administration API had the same gap on the writing side. Updating a
  delegation identified it by its identifier alone, and the permission list is
  one of the things an update can change — so an administrator of one
  organization could rewrite what another organization's delegation granted,
  and it would take effect on that person's next request. Deleting had the same
  shape, and creating accepted any person as the recipient. All of these are
  now limited to the caller's own organization, creation checks that the
  recipient, the granting administrator and the stated scope all belong to it,
  and the list's total count no longer counts every organization's records.

  Not changed, and stated plainly because it is worth a decision rather than an
  assumption: a delegation records a scope — a group, an application — and
  nothing consults it. The check that decides a request compares only what is
  being done, not where, so a delegation scoped to one group grants its powers
  wherever that power is checked. Narrowing it would take administrative access
  away from people who have it today, so it is documented rather than changed.
- **A remote session onto another organization's machine, with that
  organization's password** (migration v151). A brokered connection record is
  the definition of a privileged target: which machine, which port, which
  stored credential is typed into the session on the user's behalf, and whether
  the session needs an approval, a live supervisor, or a recording. The record
  carried nothing saying which organization it belonged to.

  The endpoint that opens a session is available to any signed-in user, which
  is correct — it is how a person launches the access they have been granted.
  It asked which organization the caller belonged to, refused if there was
  none, and then looked the target up by its address alone, never using the
  answer. Everything after that acts on whatever record comes back: the stored
  credential is fetched with the database's own restrictions deliberately
  lifted, because the server is the thing that types it in, and a working
  connection link is handed back. So a user of one organization who knew
  another organization's route identifier received a live remote desktop or
  terminal session on that organization's machine, signed in with that
  organization's credential. The credential store's own protection was intact
  and beside the point: it had been set aside on purpose, and the unscoped
  record was what chose which secret to set it aside for.

  The approval and supervision requirements could not have stopped this. Both
  are checked against records belonging to the caller's own organization, so
  the caller's own administrator could approve the caller for someone else's
  machine and the check would pass. A two-person rule that one organization can
  satisfy alone is not a control. Restricting the connection record is what
  makes those checks mean something, and it is now restricted and enforced at
  the database level.

  The list of brokered connections had the same gap in its simplest form — no
  condition at all, so every organization's internal hostnames, ports and
  connection settings were readable by any signed-in user. It is now
  administrator-only and limited to the viewer's own organization; the list end
  users see for launching their own access is unchanged and shows no
  infrastructure.

  Removed with it: a connection-token cache table that has been empty on every
  installation since it was introduced. Nothing read it, nothing called the
  code that filled it, and the statement meant to write to it referenced a
  constraint the table does not have, so every attempt failed silently into a
  log line. A later change widened one of its columns so the tokens it stored
  would be encrypted; there were never any tokens.
- **Every organization's remote support history was on every organization's
  console** (migration v150). A remote support session is an administrator
  watching or driving an end user's screen. The list of them ran with no
  condition restricting it to the viewer's own organization — so any
  administrator could see whose screen had been taken over, by which
  administrator, when, and whether a recording of it exists, across every
  organization on the installation. It is now filtered, and the table is
  enforced at the database level like the rest.

  Turning that enforcement on was not straightforward. The organization column
  on these rows has been optional since it was added, and the code that starts
  a session wrote it empty whenever the caller had no organization resolved.
  Enforcing on an optional column does not restrict those rows — it makes them
  vanish: the administrator who started such a session could no longer see it,
  end it, or delete its recording, while the session itself carried on, because
  the live connection is held in memory and never re-reads the record. The
  existing rows are therefore attributed to the administrator who started them
  first, the column is made mandatory, and only then is enforcement switched
  on. Starting a session without an organization is now refused outright rather
  than accepted and lost.

  The paths a device uses — answering the consent prompt, asking whether a
  session is waiting for it, and ending one — are deliberately exempt, because
  the device authenticates as itself and not as a member of an organization.
  Without that exemption an end user's machine could never be helped: the
  administrator would start a session the device never sees. The background job
  that expires stalled sessions is exempt for the same kind of reason — one it
  cannot see is one that never ages out.
- **One tenant could release another tenant's legal hold, and the recording was
  then deleted** (migration v149). A legal hold marks a session recording as
  evidence: while one is active, the job that enforces retention must leave the
  recording alone. Releasing a hold is therefore not a status change — it is
  what allows the next retention run to delete the recording.

  The release endpoint for remote-support recordings identified the hold by the
  session it belonged to and nothing else, so an administrator of one
  organization who knew another organization's session identifier could release
  that organization's hold. The recording it was protecting was deleted at the
  next retention run — irreversibly, and with almost nothing to see afterwards:
  the owning organization finds only a release timestamp attributed to an
  account that is not theirs. Placing and listing holds were unrestricted in the
  same way, which also exposed the stated reason for each hold, free text that
  routinely describes an ongoing investigation.

  The equivalent endpoints for privileged-session recordings did check that the
  session belonged to the caller, which is how the gap was noticeable at all —
  two implementations of one control, one guarded and one not. That check was
  also weaker than it appeared: it had no organization condition of its own and
  relied entirely on database-level enforcement, which does not apply when the
  application connects with a privileged database account. Both hold tables now
  carry an organization, the enforcement applies to them directly, and every
  endpoint names the organization in its own query rather than delegating.

  The retention sweeps remain deliberately install-wide and now say so where
  they run: a hold a sweep cannot see reads as no hold at all, so narrowing
  those queries would turn a retention job into a way of destroying evidence.
- **Temporary vendor access is under the row-level-security belt, and its usage
  record has a tenant** (migration v148). A temporary access link grants an
  outside party SSH, RDP or VNC into an internal host. An earlier migration
  (v71) had already stopped one tenant from reading or revoking another's links,
  and recorded why it went no further: the page that redeems a link runs with no
  signed-in user, so enforcing tenancy in the database would have broken
  redemption for the vendor, and every management screen was already filtered in
  code. The first reason no longer holds — the same pattern has since been
  solved four times over for other single-use secrets, most recently magic
  links, which redeem exactly this way — so redemption now runs with the
  enforcement deliberately lifted and the link's own organization carried
  through, and the links table is enforced like every other.

  The second reason is why the enforcement is worth having. It guards the next
  query written, not the ones audited when it goes in, and that query was
  already present: the record of who redeemed a link, from which address and
  with what browser, had no tenant column at all and was read by link alone —
  correct only because a separate check happened to run first. It now carries
  its own organization and is filtered on it.

  Two failures on the redemption path are fixed with it: the use counter and the
  usage record were both written without checking whether the write succeeded,
  so an unrecorded connection to an internal host would have gone unnoticed. The
  background sweep that expires stale links stays deliberately install-wide — a
  link past its expiry is expired for everyone, and a sweep that missed a tenant
  would leave a vendor connected — and now says so at the call site instead of
  being silently reduced to nothing by the new enforcement.
- **Breach response is per tenant, and its containment now does what it
  reports** (migration v147). `breach_incidents` and `breach_alerts` — the
  record of what was detected, which users and sessions it affected and what
  containment was applied — had no `org_id`. The console's incident list ran
  with no organization predicate at all, the alert feed filtered only on
  whether an alert had been acknowledged while each alert names a user, a
  session and an IP address, and the pattern analysis aggregated the whole
  install. Both tables now carry `org_id` under FORCE RLS, with existing
  incidents attributed through the users they name and alerts through their
  incident.

  The containment itself was the sharper half. Triggering incident response
  took a bare incident id, while the actions it invokes — disabling the
  affected users and revoking their sessions — were already scoped to the
  caller's organization. An administrator of one tenant could therefore trigger
  response on another tenant's incident, quarantine nobody, and leave that
  tenant's real incident marked as investigated with containment steps recorded
  against it. The incident is now scoped too, so the request is refused rather
  than silently doing nothing.

  Three further failures on the same path are fixed, each of which had been
  invisible because its error was discarded: the full quarantine wrote a
  `status` column that does not exist on the users table (every other disable
  path in the product sets `enabled = false`), so it reported disabling users
  it had not disabled — in its own tenant, not only across tenants; the update
  that records what containment ran wrote a `containment_steps` column no
  migration had ever created, so the quarantine action was never recorded
  either and the incident list showed `none` for fully quarantined incidents
  (v147 adds the column); and both list queries discarded row-scan errors and
  appended a blank row, so a single alert with no session — what the detector
  writes whenever it has no session id — truncated the whole alert list to one
  empty entry with no error shown.
- **The remaining second factors got a tenant** (migration v146). OpenIDX
  offers six second factors; three of them — TOTP, push and WebAuthn — already
  carried `org_id` and sat behind the row-level-security belt, and three did
  not: `mfa_sms`, `mfa_email_otp` and `mfa_phone_call`, along with
  `mfa_otp_challenges`, which holds the code hash, the recipient (a real phone
  number or e-mail address) and the requester's IP for every one-time code in
  flight. The administration console's MFA enrolment report listed all six side
  by side, three of its subqueries carrying an organization predicate and three
  not, under a comment recording the asymmetry as a property of the schema. No
  tenant could read another's rows — every query is keyed on the user, and a
  user belongs to one organization — so this is depth rather than a fixed
  disclosure; what it closes is the absence of any structural guarantee that it
  stays that way, and a challenge whose status and attempt counter were updated
  by bare id. It also completes a pair v143 left half-done: that migration
  belted the phone-call challenges without belting the enrolment they are
  issued against. The enrolment reads on the sign-in path run with the belt
  deliberately lifted and the tenant in the query instead, because the code
  that decides whether to demand a second factor reads an invisible enrolment
  as an absent one — under the belt alone, a user whose only factor is SMS
  would have signed in without it. The per-user uniqueness on each enrolment is
  deliberately left alone rather than made per-organization: the user already
  determines the organization, so a per-organization key would accept strictly
  more rows, and the extra rows are one user enrolled twice. Existing rows are
  attributed to their user.
- **The credentials that stand in for a password got a tenant** (migration
  v145). `hardware_tokens`, `hardware_token_events`, `mfa_bypass_codes`,
  `mfa_bypass_audit` and `magic_links` — five ways to authenticate without the
  password, none of which carried an organization. `hardware_tokens` is an
  inventory of physical tokens, holding the serial and the HOTP/TOTP seed, and
  every call site read and wrote it install-wide: the console's inventory page
  listed every tenant's tokens, and assignment took a bare token id *and* a
  bare user id, so an administrator could bind a token sitting available in
  another tenant's inventory to one of their own users — a transfer of a
  working second factor, not a disclosure of one. Bypass codes are the
  break-glass credential for getting a user past MFA: revoking one took a bare
  code id and revoking all of a user's took a bare user id, so one tenant could
  destroy another's break-glass at the moment it was needed, and the bypass
  audit log's user filter was optional — the console calls it with no user,
  which returned every tenant's history of who issued and used one.
  `serial_number` was UNIQUE across the install and is now unique per
  organization: unlike a SAML entity id it resolves no tenant, so the
  install-wide key only let the first registrant veto everybody else and
  confirmed the existence of hardware another tenant owns. Verification of a
  bypass code, a hardware token and a magic link runs with the belt lifted and
  the tenant in the predicate instead, because those paths do not all have an
  organization resolved yet and an RLS-empty read there would silently retire
  the factor. Existing rows are attributed to their user, their parent token or
  code, or the primary organization.
- **The SAML surface got a tenant** (migration v144). `saml_service_providers`
  — the registry of federation partners this install acts as a SAML identity
  provider for, holding their assertion-consumer URL and the certificate the
  IdP trusts — was listed, counted, fetched, updated, certificate-rotated,
  metadata-refreshed and deleted install-wide, all by bare id. One tenant's
  administrator could enumerate another tenant's partners, repoint their
  assertions at a host of their choosing, or delete their federation.
  `saml_sessions`, the single-logout bookkeeping, joins it under FORCE RLS.
  `entity_id` deliberately keeps its install-wide uniqueness, unlike v143's
  `provider_key`: a SAML entity id is a globally unique URI by specification
  and it is what resolves the tenant on an inbound request, so a per-organization
  key would make that lookup ambiguous. That lookup, and the equivalent one on
  the single-logout path, are documented as spanning organizations for the same
  reason API-key and route lookups do.
- **The sign-in tables got a tenant** (migration v143). `social_providers` —
  the configuration behind the social sign-in buttons — was listed with the
  organization predicate inside a `LEFT JOIN`'s `ON` clause, where it filters
  nothing on the driving table, so every tenant's providers were listed to every
  tenant; get, update and delete then took a bare id with no organization at
  all. Because the sign-in path reads this table for `allowed_domains` and
  `auto_create_users`, one tenant could change which e-mail domains may sign in
  to another tenant's deployment, whether unknown visitors are provisioned
  accounts there, or delete their sign-in button. `provider_key` was also
  UNIQUE across the install, so the first tenant to register `google` took the
  key from everybody else; it is now unique per organization. `trusted_browsers`,
  `passwordless_preferences`, `user_risk_baselines` and `phone_call_challenges`
  join it under FORCE RLS: they were keyed by the organization-scoped user, but
  trusted browsers were updated by bare id and a phone-call challenge could
  carry no user at all. Existing rows are attributed to the identity provider
  they extend or to their own user, with the primary organization as fallback.
- **The unified audit stream got a tenant** (migration v142).
  `unified_audit_events` — the console's Unified Audit page, the assignment-
  and ABAC-gate decision records, the agent lifecycle log, the MCP gateway's
  tool-call log, the Ziti and Guacamole sync and the usage metering rollup —
  had no `org_id` at all, and `QueryEvents` opened `WHERE 1=1`. Every tenant's
  admin could read every tenant's audit trail: the enforcement decisions taken
  on other tenants' applications, their users' actor IPs and, through the query's
  own `users` JOIN, their users' e-mail addresses; the summary endpoint counted
  install-wide the same way. The table now carries `org_id` under FORCE RLS and
  every writer names its tenant; the two external syncs derive it from the route
  they correlate to. Existing rows are attributed to their own user's
  organization, else the organization of the route they name, else the primary
  organization for controller-level events that match neither. Usage metering
  now reads the event's own `org_id` instead of joining `users`, so overlay
  traffic with no user attached is billed to the tenant that ran it rather than
  to an unowned bucket.
- **The compliance record got a tenant** (migration v141). `admin_audit_log`,
  `audit_archives` and `audit_retention_policies` had no `org_id` at all, and
  every handler read them accordingly: the admin log was listed `WHERE 1=1` and
  fetched by bare id, so one tenant's admin could read another's full
  administrative history including the before/after state of changes they had
  no access to make; retention policies were updated and deleted by bare id;
  and archives were listed, fetched **and restored** by bare id, so a tenant
  could name another tenant's export and have the product read that file back.
  All three now carry `org_id` under FORCE RLS, attributed to their own actor's
  organization where one survives.
- **The FORCE-RLS belt extended to fifteen more tables** (migration v140):
  `scheduled_reports`, `detailed_compliance_reports`,
  `audit_webhook_subscriptions`, `usage_metering_daily`, `email_branding`,
  `device_trust_settings`, `pam_active_checkouts`,
  `pam_checkout_authorizations`, `brokered_sessions`, `ssh_ca`,
  `sod_violations`, `privileged_accounts_discovered`, `entitlement_warehouse`,
  `upstream_pools` and `upstream_pool_members` carried `org_id` for as long as
  nine migrations with nothing underneath it, so a single query that forgot its
  predicate would have crossed tenants silently. Four also get `org_id NOT
  NULL`: under a belt, a NULL org is a row nobody can see rather than a row
  that is loudly wrong. `tools/orgscope`'s registers drop from 95 tables to 80.
- **ABAC actually decides something** — `internal/abac`, `ABAC_ENFORCE=off|observe|enforce`,
  wired at both enforcement points (the token endpoint and the access proxy).
  The admin page had authored allow/deny rules that no enforcement point
  consulted.
- **A Definition of Done that CI proves**: the smoke stack, the browser journey
  suite, a `kind` Helm install, `docs` under `--strict`, and the security scans
  gating rather than reporting.
- **Governance (IGA) guide page** — the site had PAM and ZTNA and called it four
  pillars.
- **`scripts/check-docs-drift.sh`** — no document may cite a repo path that is
  not there. Its first run found fifty broken citations.
- **`scripts/check-release-signing.sh`** — a release artifact's name must track
  the key that signed it.
- **`VERSION` + `scripts/check-version-sync.sh`** — the tree carried five answers
  to "what version is this?".
- Every published OpenAPI spec is proven against its binary's route table in
  both directions: 445 documented operations became 1,143 of 1,143.

### Fixed

- **A delegation's scope said more than it did.** The Delegated Administration
  page lets an admin scope a delegation to a Group, Role or Application,
  validates it, shows it as a badge — and the permission check compares resource
  and action only, so the delegated permissions applied wherever that permission
  was checked. The page now marks every narrowing scope **"not enforced"**, the
  create form explains what that means, and the governance guide says to grant
  the smallest permission set rather than rely on the scope. An `organization`
  scope is genuinely enforced (by the tenant predicate the delegation is read
  under) and is not marked. Enforcing the others needs the resource identity of
  each request, which the middleware does not have, and would silently revoke
  access someone is relying on — a product decision, now recorded as one instead
  of implied by a badge.

- **The clientless SSH relay never checked the host key.** `ws_connect.go`
  passed `ssh.InsecureIgnoreHostKey()` unconditionally, under a comment calling
  per-entry pinning "a follow-up" — so a PAM entry could carry a host key and
  nothing would look at it. An entry's `settings.ssh_host_key` (one
  `authorized_keys` line; no migration, the settings column is free-form) is now
  **enforced** via `ssh.FixedHostKey`: a different key fails the connection, and
  a stored key that will not parse fails it too rather than falling back to
  accepting anything. An entry with no pin connects as before and says so — a
  Warn log and `host_key_pinned: false` on the `pam.ws_connect` audit event —
  and `PAM_SSH_REQUIRE_HOST_KEY=true` refuses unpinned entries outright.

- **The 759 `go/log-injection` findings have a verdict, pinned by a test.** Log
  injection is forging a record with CR/LF in a user-supplied value. What
  prevents it here is the encoder, not a sanitiser at 759 call sites: production
  logs JSON, and zap's console encoder still writes structured *fields* as JSON,
  so a newline in a `zap.String` value comes out escaped either way.
  `TestUserValuesInFieldsCannotForgeALogRecord` encodes a forged value through
  both encoders and fails if a raw line break survives — and pins the one shape
  that *would* be a defect, a user value interpolated into the log message,
  which the console encoder writes verbatim. A sweep for that shape finds four
  sites, all interpolating configuration, none user input.

- **Every CodeQL finding at security severity 7.0+ now has a written verdict.**
  `docs/evidence/codeql-triage.md` lists all 40 (27 Go, 13 JS) with the evidence
  for each: what is vendored, what is a protocol requirement, what is already
  sanitised, what is admin-configured, and the one that was a real finding and
  is fixed. A verdict recorded in the code-scanning UI is keyed to an alert
  fingerprint and evaporates when a refactor moves the line — one alert in that
  list had been dismissed once already and came back for exactly that reason.
  The code-scanning results check passes: the one high-severity result in
  changed code was the SSH host key, and fixing it took the count to zero.

- **A token test that failed about as often as a run was slow.**
  `TestTokenService_WithConfig` asserted a token's expiry was within one second
  of a `time.Now()` taken *after* the token was minted. The expiry is
  `mint + 30m` serialised as a JWT `NumericDate`, which carries whole seconds,
  so the difference measured is the elapsed time **plus** a truncation uniform
  on [0s, 1s) -- half the tolerance gone on average before any work happened,
  and any measurable delay pushing a fraction of runs over. The failure rate is
  roughly the elapsed time in seconds: invisible locally, occasional under the
  race detector, certain across enough runs. The assertion now brackets the
  mint and requires the expiry to land in the window the mint could have
  produced, which no amount of slowness moves; setting the duration to 31
  minutes still fails it.

- **A CodeQL config that excluded nothing is gone.** An earlier commit on this
  branch added `.github/codeql/codeql-config.yml` with
  `paths-ignore: agent/third_party`, to keep nine findings in a vendored
  library out of the reader's way. The next analysis produced all nine: a Go
  database is whatever the build compiled, and the path filter is honoured for
  interpreted languages only. A file whose comment claimed it narrowed what was
  scanned, and did not, is the defect class this release spent itself deleting,
  so it is deleted too — `.github/workflows/codeql.yml` now carries the reason
  at the step where the next person would reach for one, and the nine vendored
  findings are on the dismissal list in the triage file where they belong.

- **A second migration system that applied nothing.** `migrations/` held 105
  files and a README calling itself "Database Migration System"; nothing in the
  repository has ever read them. Every service applies the registry in
  `internal/migrations` (Go constants, `loader.go`, v1–v172), and the loose tree
  had stalled at 52 with numbering that never matched — its
  `008_add_scim_identity_tables` is `audit_compliance` in the registry. Worse,
  `openidx migrate create` wrote into it, so a contributor's new migration was
  inert while `openidx migrate up` reported success, and code had been written
  against columns only the dead tree declared. The tree is deleted;
  `openidx migrate create <name>` now writes `internal/migrations/sql_v<N>.go`
  (version taken from the registry) and prints the `loader.go` entry to add;
  `openidx db seed` falls back to `deployments/docker/seed.sql`, the file the
  `seed` service really applies, and fails loudly when no seed exists;
  `openidx paths` names the real directory. `internal/identity/README.md`'s
  schema section, which described a `users_v2`/`groups_v2`/`organizations_v2`
  schema that exists nowhere in this repository, now describes the tables the
  package really reads. `loader.go`'s `//go:build !embed_migrations` named a
  build variant that never existed and is gone.

- **A red CodeQL check named a count, never a rule.** The code-scanning results
  check fails a pull request on one alert with a security severity of 7.0 or
  higher and reports only *"N new alerts including 1 high severity security
  vulnerability"*, while both CodeQL jobs stay green — so nothing in a CI log
  said which rule, in which file. The analysis had been writing the answer to
  `../results/<language>.sarif` on the runner and throwing it away.
  `scripts/codeql-alert-summary.sh` now prints, after each analysis, every
  result at or above that floor with its rule id, file and line, plus a count
  per rule. Diagnostic only: it cannot fail the build.

- **The contract prober accepted any TLS certificate, by default.**
  `tools/contractcheck` probes a running deployment to prove the console's
  declared response shapes match what the backend actually returns — but its
  `-insecure` flag defaulted to on and the transport hard-coded a disabled
  certificate check, so a probe could pass against anything that answered on the
  address, having proved nothing about the deployment it named. Verification is
  now on unless `-insecure` is asked for, the transport takes the flag's value
  instead of a constant, and a TLS 1.2 floor applies either way. (CI is
  unaffected: it probes each service on `http://localhost:<port>`.)

- **The audit trail was not recording.** `audit_events` is behind the FORCE-RLS
  belt, and the pool sets `app.org_id` at checkout from the request context — but
  the oauth (SAML/SSO), identity and provisioning services all wrote it from a
  goroutine on a bare `context.Background()`. Each put the right organization in
  the row and none put it on the connection, so the policy's `WITH CHECK`
  refused every insert and the only trace was a WARN log. Two more of the same
  class were worse: the joiner/mover/leaver policy runner disabled leavers with
  `UPDATE users ... AND org_id = $2` on a detached context, matching its
  predicate and affecting zero rows, and bulk operations and security alerts had
  it too. All now carry the tenant on the context, and
  `scripts/check-detached-org-writes.sh` fails the build on the next one.
- **Audit archives came out empty and said they were fine.** `createAuditArchive`
  runs detached on a bare `context.Background()`, and `audit_events` sits behind
  the RLS belt — so the pool set no `app.org_id` at checkout, the policy matched
  nothing, and every archive completed reporting an event count of zero with no
  error anywhere. The worker now carries the organization that asked for the
  archive.
- **Email branding was a shared row.** Both `email_branding` handlers ignored
  the caller's organization entirely — the read was `ORDER BY created_at LIMIT
  1` and the write was `(SELECT id FROM organizations LIMIT 1)` — so on a
  multi-tenant install every admin saw, and every save overwrote, the same
  single row. Both now scope to the caller's org, and migration v140's policy
  refuses the old write at the database.
- The assignment gate, the OPA `deny` path and the SMS mock provider each failed
  **open**; they now fail closed or refuse to start.
- Five documented `/access/*` auth endpoints that returned 404 (the served
  routes are `/access/.auth/*`).
- Constants dressed as measurements: a literal 365-day uptime, a "refresh" that
  refreshed nothing, a deterministic SAML "transient" NameID.

### Removed

- The server-rendered login (`GET /oauth/login`, the five `/authorize/mfa*`
  routes, `hosted_mfa.go`) — a second credential pipeline outside every i18n and
  accessibility gate this branch built.
- `internal/feature/`, `internal/oauth/store.go`, `client/lib/api/auth.dart` and
  the Expo `mobile/` tree: dead code that read as shipped capability.

### Changed

- The README's "70–80% saving" claim — forbidden on the console's landing page
  by its own test since the truthfulness rewrite — is gone from the README too.

## [1.33.3] - 2026-08-25

_No changelog entries were recorded for this release._

**Why several releases below say that.** `[Unreleased]` was never advanced when
v1.28.0 was cut, so everything written between v1.27.0 and v1.33.3 piled up
under one heading — 359 lines that all read as unshipped. The attribution here
was recovered rather than guessed: `CHANGELOG.md` was touched exactly twice in
that window (`427592d8`, in v1.28.0, and `ddb2ba3f`, in v1.33.2), so each entry
belongs to the release containing the commit that added it. The releases in
between shipped code but wrote nothing here, and saying so is more accurate
than distributing entries across them by feel.

**There is no v1.30.0.** The version sequence skips it — no tag, no release.

## [1.33.2] - 2026-08-24

### Fixed

- **Android/iOS client no longer boots to a blank white screen.** `main()` ran
  the desktop boot path on every platform: it awaited
  `windowManager.ensureInitialized()` (and later `TrayController.init()`), but
  `window_manager` / `tray_manager` are desktop-only plugins with no method-channel
  implementation on mobile. The call threw
  `MissingPluginException(No implementation found for method ensureInitialized on
  channel window_manager)` **before `runApp()`**, so the app started, painted
  nothing, and showed no crash dialog — it just sat on white. `main()` now
  branches on `EngineClientFactory.isMobile`: mobile calls `runApp()` directly
  (leaving `engineSupervisorProvider` un-overridden so `engineClientProvider`
  builds the in-process `MobileEngineClient`), while desktop keeps the unchanged
  window-chrome + tray + sidecar-supervisor path. The rest of the mobile
  code (`MobileShell`, `SettingsScreen`) was already platform-guarded; `main.dart`
  was the only unguarded entry point. The Flutter client version also now tracks
  the release tag (`1.33.2+13302`, was `0.1.0+1`) so the installed build is
  identifiable on-device.

## [1.33.1] - 2026-08-24

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.33.0] - 2026-08-24

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.32.0] - 2026-08-24

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.31.0] - 2026-08-23

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.29.0] - 2026-08-19

_No changelog entries were recorded for this release (see the note under
[1.33.3])._

## [1.28.0] - 2026-08-18

### Added

- **Clientless remote access + Quick Links launcher + attended-support consent.**
  A user can now reach support/collaboration systems and remote connections with
  no installed client, and admins manage it centrally. (1) **In-browser SSH**
  ("wasm-ssh" renderer): a PAM SSH entry opens an xterm.js terminal in the
  browser over a WebSocket->TCP relay (`GET /api/v1/access/pam/entries/:id/ws`)
  that dials the target over the Ziti overlay — no PuTTY/guacd, the browser tab
  is the SSH client. Reuses the existing PAM permission/approval gate (enforced
  before the socket upgrade) and credential vault; the token rides as a
  `bearer.<jwt>` WS subprotocol. `pam_entries.renderer` (migration v89) selects
  guacamole (default, unchanged) vs wasm-ssh. (2) **Quick Links** (migration
  v90): an admin-curated, user-searchable launcher. `type=external` opens a safe
  URL (Teams/Zoom/status/ticketing); `type=pam` references a connection and
  launches it clientlessly via its renderer. Org-scoped + forced RLS, role-gated
  by `min_role`, unsafe URLs rejected. New user page (`/quick-links`) + admin
  CRUD (`/quick-links-admin`). (3) **Attended-support consent** (migration v91):
  a remote-support session can require the person at the device to Allow it
  before the admin can view/control — the admin WebSocket is refused (403
  "awaiting device consent") until the device grants via
  `POST /agent/remote-support/sessions/:id/consent`; a denial ends the session.
  Plus a **live view<->control toggle** in the support viewer (hand control back
  and forth without restarting). Verified live end-to-end (real SSH handshake;
  quick-links create/list/reject; consent 403->101). Also fixed a pre-existing
  bug where `remote_support_sessions` lacked `org_id`/`recording_retention_days`
  (referenced by session-start but never migrated), and a migration-runner
  dollar-quote splitter bug that broke fresh `migrate` on v89.

- **Dark platform (Ziti-first / overlay-only posture) — Phases 1-6, fully opt-in.**
  A staged path to make OpenIDX's own surfaces reachable only over the OpenZiti
  overlay, defaults preserving today's public behavior at every step. (1)
  `SERVICE_BIND_ADDR` + `DARK_MODE_TIER1/2` config and `cfg.ListenAddr()` so every
  service can bind loopback-only (verified live). (2) `#enrolled-users` on every
  identity + gated `#device-trusted`, and a reconciler `ensureTierDialPolicy`.
  (3) A single hardened public enroll door `POST /api/v1/access/enroll`
  (session/token → Ziti enrollment JWT, rate-limited + audited; verified live,
  fail-closed on every bad path). (4) `DARK_MODE={off|tier2|tier1}` edge route
  set + `scripts/dark-mode.sh` (`--verify`/`--undark`/`--self-test`) + `make
  dark-drill`. (5) The reconciler now models OpenIDX's own surfaces as tier'd
  dark Ziti services via `defaultDarkServices()` (admin-api/governance/audit/
  provisioning/scim/access → Tier 2 `#device-trusted`; identity self-service +
  console → Tier 1 `#enrolled-users`; enroll/oauth/jwks never darked), plus
  `scripts/register-console-dark-app.sh` registering the admin console as a
  BrowZer dark app (Tier-1 shell, same-origin `/api/*` tunnels to the Tier-2
  backends). (6) Staged **cutover runbook + break-glass** in
  `OPENIDX_ZITI_ARCHITECTURE.md` (enroll fleet → drill → cut Tier 2 then Tier 1
  → `--undark`), linked from `DEPLOYMENT.md`, and **mutation-tested tier
  invariants** wired into `make dark-drill` (Tier-2 surfaces must be
  `#device-trusted`; no Tier-0 surface is ever darked; dark upstreams are
  loopback). Spec/plan under `docs/superpowers/`.

- **Scoped the Tier 3b cutover: `docs/tier3b-cutover-runbook.md`.** The
  availability plan recommended moving prod off the single VM onto the
  already-written EKS/managed path but left the *cutover* itself unsequenced. New
  runbook lays out the end-to-end move: preconditions (a passing `make ha-drill`
  and a live DR game-day PASS), closing the two open infra gaps (add an OpenSearch
  Terraform module; activate the RDS read replica via `externalSecrets.readReplica`
  — everything else is wired), standing up the EKS stack in parallel on a shadow
  DNS name, the data cutover (logical replication preferred, dump/restore
  fallback), a DNS traffic cutover that deliberately flips the **DB-independent
  verify surfaces first** so token validation never stops, post-cutover
  activation/verification, and rollback at each stage. It leans on the
  always-available invariant (verification does not depend on which stack/DB is
  live) that `make dr-game-day` checks at every gate. Also surfaced and wired the
  concrete config gap it identified: `values-prod.yaml` now carries a documented
  `externalSecrets.readReplica` flag (left `false` so a fresh cutover's
  ExternalSecret doesn't reference a missing key; flip on as a follow-on step).
  Verified `helm template` renders clean with the flag both off (no
  `DATABASE_READ_URL`) and on (rendered). Linked from the availability plan and
  `DEPLOYMENT.md`.

- **Repository pattern reaches the admin god-object (`SettingsRepository`).**
  Began strangling `internal/admin/service.go` (3,439 lines — the largest
  god-object in the design-patterns review) by extracting all `system_settings`
  access into `internal/admin/settings_repository.go`. That table is a key/value
  JSON store (`system`, `sms_config`, `mfa_methods`, ...) whose identical
  `SELECT value FROM system_settings WHERE key = $1` + `INSERT ... ON CONFLICT
  (key) DO UPDATE` UPSERT was copy-pasted inline across ~6 handlers, each free to
  pick its own pool. It's now one `GetRaw`/`PutRaw` port with a typed
  `ErrSettingNotFound` and nil-db guards; `admin.Service`'s `GetSettings`/
  `UpdateSettings` + the SMS/MFA-methods handlers delegate to it. **Pool
  judgment:** reads use the **primary**, not the replica — `system_settings`
  carries password policy, `RequireMFA`, lockout, and session limits, so a
  just-tightened policy must take effect immediately (read-after-write); a lagging
  replica could briefly enforce a weaker policy. Locked by a mutation-tested
  invariant guard (`TestSettingsRepositoryGetUsesPrimary`/`WritesUsePrimary`,
  wired into `make ha-drill`; verified it fails when a write is moved to
  `.Reader()`) and unit-tested with a fake repo and no database (defaulting,
  corrupt-row fallback, write-error propagation, nil-db guards).

- **`make dr-game-day` — the data-tier failover game-day is now runnable, not a
  copy-paste runbook.** `docs/disaster-recovery.md` §1D previously described the
  RDS Multi-AZ / Patroni failover drill as manual shell steps in a comment block.
  New `scripts/dr-game-day.sh` executes it end-to-end: a synthetic auth canary
  probes `/health/live` (verify path — must stay 200 the entire window, since
  verify is DB-free/serve-stale) and `/health/ready` (issue path — may 503 while
  the LB drains new logins, then must self-recover as pgxpool re-dials the
  promoted primary), then prints a pass/fail verdict and exits non-zero on any
  contract violation. It can trigger failover itself (`--trigger --provider
  rds|patroni`) or just observe. Crucially it ships a **`--self-test` mode** that
  stands up a local stdlib mock simulating a failover window and runs the whole
  canary/verdict logic against it — so the drill is verified with no
  infrastructure and can't silently rot into a false-green (a false-green DR
  drill is worse than none). `make dr-game-day` runs that self-test; verified it
  passes on a clean window and fails correctly on both a verify-path drop and a
  non-recovering issue path.

- **`make ha-drill` — one command to verify the always-available-auth
  guarantees.** Runs the focused Go tests that encode each availability tier
  (serve-stale JWKS + Auth-survives-issuer-outage; bounded DB timeouts +
  read-replica seam; dependency-outage classification + 503 brownout + Redis
  revocation breaker) plus the mutation-tested read/write pool-safety guards. The
  wrapper (`scripts/ha-drill.sh`) fails loudly if a guarantee test is renamed or
  removed (no silent "[no tests to run]" false-green), so the drill stays
  trustworthy. Runs in ~15s with no infrastructure; complements the DR failover
  game-day. See `docs/architecture/always-available-auth-plan.md` §5.

- **Repository pattern reference implementation (identity/User).** Introduced
  `internal/identity/user_repository.go`: a `UserRepository` interface +
  `PostgresUserRepository` pgx implementation
  (`GetByID`/`GetByUsername`/`GetByEmail`/`Exists` reads via `db.Reader()`, plus
  `Create`/`Update`/`Delete` writes on the primary pool) that isolates user SQL
  into one type, scopes every query to the caller's tenant, and makes the
  primary-vs-replica choice explicit (reads offload to the Tier 1.6 replica;
  writes never do). `identity.Service.GetUser`/`GetUserByUsername`/
  `GetUserByEmail`/`CreateUser`/`UpdateUser`/`DeleteUser` now delegate to it
  (behavior-preserving; domain side effects like audit logging, deprovisioning,
  and delete ordering stay in the service). Along the way this fixed a latent
  NULL-name scan error in the username/email lookups, guarded two nil-DB
  panics (`logAuditEvent`, `deprovisionUser`), and surfaces duplicate
  username/email as a typed `ErrUserAlreadyExists` (409). This is the template
  for splitting the god-object services (see
  `docs/architecture/design-patterns-review.md`). Business logic (full CRUD) is
  now unit-testable with a fake repo and no database (`user_repository_test.go`).

- **Repository pattern — second aggregate (identity/Group).** `Group` is now
  behind `GroupRepository` (`internal/identity/group_repository.go`) following the
  same template: `GetByID`/`GetByName` reads on the replica, `Create`/`Update`/
  `Delete` writes on the primary (Delete removes memberships then the group row),
  typed `ErrGroupNotFound`/`ErrGroupAlreadyExists`. `identity.Service`'s
  `GetGroup`/`GetGroupByDisplayName`/`CreateGroup`/`UpdateGroup`/`DeleteGroup`
  delegate to it. Unit-tested with a fake repo and no database
  (`group_repository_test.go`).

- **Repository pattern — third aggregate (identity/Session).**
  `SessionRepository` (`internal/identity/session_repository.go`) demonstrates
  per-query pool judgment: lag-tolerant reads (`ListByUser`/`CountActive`) use the
  replica, while `IsValid` deliberately reads the **primary** because session
  validity is a read-after-write security check (a just-revoked session must not
  read as valid off a lagging replica). Writes (`Create`/`UpdateActivity`/
  `Terminate`) use the primary. `identity.Service`'s `GetUserSessions`/
  `CreateSession`/`UpdateSessionActivity`/`IsSessionValid`/`CountActiveSessions`/
  `TerminateSession` delegate to it. The security-critical primary read is locked
  by a mutation-tested guard (`TestSecurityCriticalReadUsesPrimary`), and the
  writes-never-replica guard now covers all three repositories. Unit-tested with a
  fake repo and no database (`session_repository_test.go`).

- **Repository pattern generalizes to the oauth service (OAuth clients).** OAuth
  client CRUD is now behind `OAuthClientStore`
  (`internal/oauth/oauth_client_store.go`): `GetByClientID` reads the primary
  (client validation gates every token grant and checks the secret), `List` reads
  the replica, and `Create`/`Update`/`Delete` write the primary.
  `oauth.Service`'s `GetClient`/`ListClients`/`CreateClient`/`UpdateClient`/
  `DeleteClient` delegate to it; guarded by a mutation-tested invariant test and
  unit-tested with a fake store and no database. Also documented a pre-existing
  smell surfaced by this work: the oauth package has a *separate* `ClientRepository`
  (`client.go`, used by `token_flow.go`) that models the same `oauth_clients` table
  differently — a worthwhile unification follow-up (see
  `docs/architecture/design-patterns-review.md`). **(Resolved below in
  Removed — that duplicate turned out to be unwired, security-divergent dead code
  and was deleted.)**

### Fixed


- **Admin-console unit tests can run again (frontend test env repaired).**
  `vitest.config.ts` requested `environment: 'happy-dom'`, but `happy-dom` was
  never in `package.json` (only `jsdom` is a pinned devDependency), so `npm test`
  / CI's `npm test -- --run` died immediately with `ERR_MODULE_NOT_FOUND` and
  ran **zero** tests. Switched the config to the installed `jsdom` environment
  and added the one jsdom shim happy-dom provided that Radix UI needs:
  `Element.prototype.scrollIntoView` (a no-op mock in `src/test/setup.ts`),
  which `@radix-ui/react-select` calls on mount and which otherwise threw
  `candidate?.scrollIntoView is not a function` and failed every Select-based
  test. Result: the full suite now runs green — **761 tests across 122 files
  pass** (previously: could not start). This also unblocks the `ci-web`
  pipeline. No new dependency added.

### Security

- **Closed ~170 server-error information-disclosure sites: 5xx responses no
  longer leak `err.Error()` to clients.** Handlers across 30+ files (access/Ziti,
  identity MFA/risk, vault, credentials, audit, organization, portal, oauth
  client-management) were returning the raw wrapped error
  (`c.JSON(500, gin.H{"error": err.Error()})`) — which can expose SQL fragments,
  hostnames, driver text, and internal paths. Every 5xx `err.Error()` leak was
  migrated to the typed renderer `apperrors.HandleErrorWithLogger(c,
  apperrors.Internal("<action>", err), logger)`, which returns a safe, typed body
  (`{"error":"INTERNAL_ERROR","message":"<action>"}`) to the client while logging
  the real cause server-side with request-id/path context. Where a handler
  already logged the error immediately before leaking it, that now-redundant log
  line was removed to avoid double-logging (the renderer logs). Protocol
  endpoints kept their RFC 6749 shape (e.g. the OAuth authorize/consent path
  still returns `{"error":"server_error"}`, now with a static
  `error_description` instead of the raw error). A count check enforces zero
  remaining 5xx `err.Error()` leaks. **Surfaced and fixed a latent bug in the
  process:** `portal.ReviewGroupRequest` returned its "invalid decision"
  *validation* error as a 500 leak; it now returns a typed `ErrInvalidDecision`
  sentinel that the handler maps to a proper 400. `go build ./...`,
  `go vet ./...`, and the touched-package tests all pass.

### Removed

- **Collapsed the admin-console's two parallel API clients — deleted the entire
  dead `src/lib/api/` directory (client + domain wrappers + barrel; ~800 lines).**
  The console had two API layers: the live `src/lib/api.ts` (the `api` object,
  imported by ~199 modules) and a second, separate `src/lib/api/` package
  (`client.ts` axios instance + `admin`/`audit`/`governance`/`identity` wrappers +
  `types.ts` + an `index.ts` barrel re-exporting `apiClient as api`). Because a
  file (`api.ts`) wins module resolution over a same-named directory
  (`api/index.ts`), **every `@/lib/api` import hit `api.ts` and the whole
  directory had zero live importers** — a classic duplicate-that-can-drift trap
  (the two clients had already diverged on token-storage keys and the
  refresh-token endpoint, both fixed earlier). Verified exhaustively that nothing
  outside the directory imported any of its modules, then removed it. The one
  place that referenced it — `dashboard.test.tsx` — was `vi.mock()`-ing the dead
  `./lib/api/client` while the component under test actually imports `{ api }`
  from `../lib/api`, so the mock was inert; retargeted it to mock the real
  `../lib/api`, which also makes the test's stubbing actually take effect.
  `tsc --noEmit`, the full vitest suite (746 tests / 121 files pass; the −15 vs
  before are exactly the deleted `audit.test.ts` that only tested the dead
  `auditApi`), and `vite build` all pass.

- **Deleted a dead, security-divergent duplicate OAuth/OIDC pipeline
  (`client.go`, `authorize_flow.go`, `token_flow.go`; ~3,100 lines incl. tests).**
  The oauth package carried a second, fully parallel implementation
  (`Client` / `ClientRepository` / `AuthorizeFlow` / `TokenFlow`) operating on the
  same `oauth_clients` table as the live `OAuthClient` / `OAuthClientStore`, but it
  was **never wired to a live route** — only reachable from tests. It had also
  already diverged from the live path on a security check: the dead
  `ClientRepository.ValidateRedirectURI` permitted wildcard-subdomain redirect
  URIs (`https://*.example.com`, an open-redirect risk), while the live authorize
  handler requires exact byte-equality. Two representations of one table that can
  disagree — and insecure dead code invites someone to wire it — so the cluster
  was removed. The authoritative representation is `OAuthClient` (+
  `OAuthClientStore`); live token/authorize/userinfo flows remain in
  `service.go` / `authorize.go`. The three genuinely-live symbols the cluster
  exported (`TokenFlowResponse`, `generateUUID`, and the RFC 6749 error-code
  constants used by the 503 brownout path) were preserved in a small new
  `internal/oauth/oauth_types.go`. Redundant validation tests were dropped only
  after confirming equivalent live coverage
  (`TestAuthorizeHandler_ValidateRedirectURI`, `TestValidatePKCE`,
  `TestSecurityFeatures`); `TestOAuthConstants` was retargeted onto the preserved
  constants. `go build ./...`, `go vet ./...`, and `go test ./internal/oauth/`
  all pass. See `docs/architecture/design-patterns-review.md` §1.

### Changed

- **Hardened the shared error renderer (`internal/common/errors`).** `HandleError`
  now guarantees the client only sees safe, typed fields (never the wrapped
  internal error), and a new `HandleErrorWithLogger(c, err, logger)` logs the real
  cause server-side for 5xx (with request id + path) instead of silently dropping
  it. Closes an information-disclosure vector and an observability gap. Tests in
  `render_test.go` verify a DB error containing a password/hostname is logged but
  not leaked to the response body. First adopters migrated in
  `internal/identity/handlers_otp.go` (internal-error sites that previously
  discarded the underlying error now log it via `HandleErrorWithLogger`).

- **Always-available authentication — Tier 0 (verify-path survives a DB outage).**
  Token *verification* (validating an already-issued JWT) is now hardened to keep
  working through an outage of the OAuth/JWKS endpoint and the shared database:
  - **Serve-stale JWKS.** The shared verify path
    (`internal/common/middleware`, used by all services) and the gateway JWT
    middleware now keep serving the last successfully fetched signing keys when a
    JWKS refresh fails, bounded by `JWKS_MAX_STALE` (default 12h) past the
    `JWKS_TTL` freshness window (default 1h). Previously a failed refresh after
    cache expiry rejected otherwise-valid tokens, turning a database blip into an
    auth outage.
  - **Metrics + alerts.** New `openidx_jwks_refresh_failures_total`,
    `openidx_jwks_serve_stale_total`, and `openidx_jwks_stale_seconds`, with a
    `openidx.jwks_availability` PrometheusRule group (issuer-down, serving-stale,
    and near-max-stale alerts).
  - **Liveness/readiness probe split.** Every Helm service pointed both probes at
    `/health` (which 503s when the shared DB is down), so a DB blip would restart
    every pod at once and wipe warm JWKS caches. Liveness now uses `/health/live`
    (process-only), readiness uses `/health/ready` (drains from the LB on a
    critical dependency outage), for graceful degradation instead of a crash-loop.
  - Docs: `docs/architecture/always-available-auth-plan.md`.

- **Always-available authentication — Tier 1 (issue path survives DB failover).**
  - **Bounded DB connect timeout.** pgxpool's default `ConnectTimeout` was 0
    (unbounded), so a runtime reconnect to a dead primary during an RDS/Patroni
    failover could hang for minutes, pin the request, and exhaust the pool — a DB
    failover cascading into a service-wide outage. `internal/common/database` now
    sets a 5s connect timeout (`DB_CONNECT_TIMEOUT`) so failover fails fast and the
    pool re-dials the promoted primary.
  - **Optional per-statement timeout** (`DB_STATEMENT_TIMEOUT`, 30s in prod
    values) so a query on a degraded primary can't hold a connection open forever.
    Off by default; migrations run out-of-band and are unaffected.
  - Wired through the Helm configmap (`database.connectTimeout` /
    `database.statementTimeout`), set in `values-prod.yaml`. Tests:
    `internal/common/database/pool_config_test.go`. Added a Postgres failover
    game-day to the DR runbook.
  - **Optional read-replica pool.** `DATABASE_READ_URL` opens a second read-only
    pool exposed via `(*PostgresDB).Reader()`, which falls back to the primary
    when no replica is configured (correct-by-construction call sites). A replica
    outage never fails startup (degrades to primary-only) and is surfaced by a
    new non-critical `database_replica` health check. Delivered via the external
    secret store (`externalSecrets.readReplica`). Query call sites are not
    auto-routed — adoption is per-query where read-after-write is not required.
    Tests: `read_replica_test.go`, `read_replica_checker_test.go`.

- **Always-available authentication — Tier 2 (graceful brownout on the issue path).**
  Added `internal/oauth/unavailable.go`: a classifier that distinguishes a
  transient dependency outage (Postgres/Redis unreachable, pool exhausted, dial
  timeout, `57P0x`/`08xxx`/`53300`/`25006` SQLSTATEs, network errors) from a
  genuine application error, and returns RFC 6749 `503 temporarily_unavailable`
  with a `Retry-After` header for the former (clients back off and retry) while
  keeping `500 server_error` for the latter. Applied to the DB-backed OAuth
  issue-path sites (authorization-code creation, refresh-grant user-status
  check), so a database failover degrades login to a brief, retryable brownout
  instead of a hammered 500. Tests: `internal/oauth/unavailable_test.go`.
  - **Redis revocation-check circuit breaker.** `IsAccessTokenRevoked` (the
    hot-path revocation read used by token introspection/verification) now runs
    its Redis reads through a circuit breaker (`oauth-redis-revocation`,
    threshold 5, 5s reset). During a Redis brownout the breaker opens and the
    check fails fast instead of every request paying the 3s Redis read timeout.
    Callers already fail closed on error, so opening the breaker changes cost, not
    security. Observable via `openidx_circuit_breaker_state{name=
    "oauth-redis-revocation"}` (existing `CircuitBreakerOpen` alert). Test:
    `internal/oauth/revocation_breaker_test.go`.

- **Always-available authentication — Tier 3 (infra for HA prod).** The Terraform
  RDS module now provisions optional read replica(s) (`read_replica_count`,
  defaulted to 1 in prod / 0 in dev) and exposes `rds_reader_endpoints` /
  `rds_reader_addresses`. This is the managed reader endpoint the Tier 1.6
  `DATABASE_READ_URL` app seam points at — previously the app supported a read
  pool that prod had no way to create. Wire the output into the external secret
  `.../database-read-url` and set `externalSecrets.readReplica=true` to activate
  it. (`deployments/terraform/modules/rds`, `deployments/terraform/main.tf`.)

## [1.27.0] - 2026-07-13

### Added

- **PAM per-connection broker routing — direct vs OpenZiti (#439)** — each connection
  entry selects a `reach_mode`: `direct` (guacd dials the target) or `ziti` (guacd →
  loopback → ziti-tunnel → OpenZiti overlay → target, no inbound target exposure).
  Migration **v82** adds `reach_mode`/`ziti_service_name`/`ziti_intercept_port` to
  `pam_entries`.
- **PAM dedicated session brokers — deploy artifacts (#440)** — opt-in docker-compose
  overlay and Helm templates for two isolated Guacamole brokers (direct + ziti) with
  their own DB and admin credentials, kept separate from any shared Guacamole. Gated by
  `pamBroker.enabled` (default off → zero manifests).
- **Split internal vs browser-facing Guacamole URL (#441)** — `GUACAMOLE_PUBLIC_URL` /
  `GUACAMOLE_ZITI_PUBLIC_URL`: the access service dials the internal broker for the REST
  API but hands the browser a reverse-proxy-reachable connect URL. Falls back to the
  internal URL when unset.

### Fixed

- **Brokered PAM launch was not idempotent (#441)** — the Guacamole connection name is
  deterministic (`pam-<entryID>`); once created, a relaunch without a persisted connection
  id hit Guacamole's `409/400 "already exists"` → 500. Now the launcher looks the
  connection up by name, updates it in place, and reuses it.
- **SAML service-provider schema drift** — `internal/oauth/saml_sp.go` read/wrote columns
  (`description`, `metadata_url`, `want_assertions_signed`, `encryption_enabled`,
  `last_used_at`) that no migration had created, so the SP admin list/create/update paths
  errored with `42703`. Migration **v83** reconciles the table (additive; TEXT columns
  `NOT NULL DEFAULT ''`, booleans default false, `last_used_at` nullable).

### Migrations

- **v82** — `pam_entries` reach mode (direct|ziti) columns + partial unique index on the
  ziti intercept port.
- **v83** — `saml_service_providers` column reconcile.

## [1.26.0] - 2026-07-12

### Added

- **PAM connection manager — RDM parity (#437)** — a Remote Desktop Manager-style privileged
  connection tree for brokered, passwordless sessions:
  - Folders/entries model (`pam_folders`, `pam_entries`) with tags, per-entry policy flags
    (`allow_reveal`, `require_approval`, `record_session`), grants (`pam_entry_grants`),
    favorites, access requests, and a session ledger (`pam_entry_sessions`) — all org-scoped
    under FORCE RLS.
  - Import path for existing connection inventories and a launch path that opens brokered
    sessions without exposing the underlying vault credential.
  - New **PAM Connections** console page (`/pam-connections`) and API client wiring; nav entry
    under the Privileged Access section.
  - CR/LF scrubbing on user-derived values in the import/launch log lines.

### Migrations

- **v81** (additive) — `pam_folders`, `pam_entries`, `pam_entry_grants`, `pam_entry_favorites`,
  `pam_entry_access_requests`, `pam_entry_sessions` with per-table org-scope RLS policies and
  `openidx_app` grants.

## [1.25.0] - 2026-07-12

Large security-and-correctness release (workstreams WS-01…WS-05) plus cross-pillar
correlation, OAuth signing-key rotation, PAM self-service, and a substantial dead-code
purge. Schema advances **v68 → v80** (migrations v69–v80, all additive). Deployed to the
reference box via a full catch-up (schema v68→v80, 8-binary swap); functional sweep of all
services clean.

### Security

- **OAuth step-up MFA bypass closed (WS-01)** — the step-up flow no longer rubber-stamps MFA,
  and MFA-gating can't be bypassed; the authorize-consent subject is derived from the session,
  not the request body.
- **Cross-tenant IDOR fixes (WS-03)** — tenant-scoped `published_apps`/`discovered_paths`,
  `temp_access_links`, and `device_trust_requests`; `GET /organizations` no longer enumerates
  other tenants and org write paths are authorized; Elasticsearch audit search is tenant-scoped;
  portal device registration now stamps the caller's `org_id` (was mis-tenanted to the default org).
- **Minted API keys now actually authenticate requests (WS-03)** — previously issued keys were inert.
- **Separation-of-duty enforced and fail-closed (WS-05)** — SoD policies are evaluated at
  access-request fulfillment and in identity; evaluation failures fail closed.
- **Fail-open hardening** — `CheckPolicies` fails closed when org context is absent; three
  fail-open error paths in the live security checks are closed. Approval policies'
  `auto_approve_conditions` evaluate fail-closed.
- **Log-injection sanitization** — CR/LF and user-derived values scrubbed from cross-pillar,
  step-up MFA, and IBDR/continuous-auth log lines (CodeQL).

### Added

- **Cross-pillar correlation** — correlate IAM, PAM, and Ziti per user: unified access map,
  kill switch, and lifecycle propagation; a user's devices are correlated across IAM trust and
  Ziti compliance.
- **OAuth DB-backed signing-key rotation** — `oauth_signing_keys` (migration v79) backs rotatable
  RS256 signing keys.
- **Governance (WS-05)** — audit + session-kill on access-review revocation; manager-based
  reviewer resolution; `org_id` + FORCE RLS on certification/ABAC tables; JIT expiry now revokes
  application access.
- **Provisioning** — provisioning rules are evaluated on SCIM user create/update (safe additive
  subset); SCIM `filter` applied in `ListSCIMUsers`/`ListSCIMGroups`.
- **Audit** — `detailed_compliance_reports` table (migration v74) with org-scoped evidence access;
  GDPR report routed; WebAuthn MFA counted from `mfa_webauthn` in SOC2/ISO metrics.
- **Identity** — `known_devices.device_type` (migrations v75/v76) so corporate-device
  auto-approval works.
- **PAM finalization — end-user self-service** — non-admin users get a first-class PAM surface:
  - `GET /api/v1/access/guacamole/my-connections` — org-scoped catalog of brokered Guacamole
    connections with the PAM flags the launcher needs (approval required / recorded /
    credential injected); never exposes the vault secret id or Guacamole-internal identifiers.
  - `GET /api/v1/access/guacamole/my-session-requests` — the caller's own session requests
    (previously only admins could list requests), joined with route info so an approved
    request can be launched.
  - New **My Privileged Access** console page (`/my-privileged-access`, in the user nav):
    launch/request brokered remote sessions, track request status, and manage JIT credential
    checkouts (one-shot retrieve + early return) in one place.
- **PAM finalization — management dashboard** — new aggregated stats endpoint
  `GET /api/v1/pam/overview` (admin-api, admin-guarded; explicit org predicates on top of
  FORCE-RLS) covering vault inventory by type, rotation health (enabled/failing/overdue
  policies, 30-day runs/failures), checkout activity (active leases, 30-day checkouts,
  pending JIT credential requests), and privileged sessions (active, 30-day, pending
  approvals, recordings on legal hold). New **PAM Dashboard** console page
  (`/pam-dashboard`) renders it with health labels and manage links; linked from the
  dashboard's Privileged Access card and the Privileged Access nav section.

### Changed

- **Admin PAM routes are now role-gated client-side** — `/pam-dashboard`, `/vault-secrets`,
  `/rotation-policies`, and `/guacamole-sessions` no longer mount for non-admins (redirect
  to the dashboard); the backend 403 remains the enforcement layer. Vault Secrets and
  Privileged Sessions now render a friendly "admin access required" state on 403 (matching
  Rotation Policies) instead of a generic failure.
- **Legal-hold reasons via a proper dialog** — the Session History place/release legal-hold
  flow uses an accessible reason dialog (reason required to place a hold) instead of
  `window.prompt`.

### Fixed

- **Governance revocation actually revokes** — access-review revoke decisions now revoke access;
  role-based approval steps get real approvers; stopped silent audit loss on JIT grant/expiry.
- **"Phantom table" correctness sweep** — features now read the real schema instead of
  never-created tables: MFA/WebAuthn metrics from `mfa_webauthn` (not `webauthn_credentials`),
  GDPR consent from `user_consents` (not `consent_records`), user groups from `group_memberships`
  (not `user_groups`), breach detection and continuous auth on real tables, MFA method status and
  biometric/passwordless from real enrollment tables.
- **Risk** — admin-configured risk policies are applied (was a `parseJSON` no-op); device tracking
  uses real `known_devices` columns; `GetUserDevices` no longer silently drops rows with NULL text
  columns.
- **Dashboard** — dropped a non-existent `users.deleted_at` predicate that errored and made the
  admin dashboard silently report zero users (#435).
- **Admin console** — reads the bare-array `/organizations` response so the tenant UI renders (WS-03).

### Removed

- **Dead-code purge (~8.8k+ lines)** — deleted five never-wired subsystems and additional dead
  paths: the OAuth `KeyManager` and its phantom `oauth_signing_keys` layer, the unrouted
  `CertificationService` and WebAuthn subsystem, the never-functional admin passwordless subsystem,
  the dead AI policy-recommendations route, and orphaned CSV-import handlers.

### Migrations

- **v69–v80** (all additive): governance org-isolation (v69), `users.manager_id` (v70),
  `temp_access_links`/`device_trust_requests`/`published_apps` tenant isolation (v71–v73),
  `detailed_compliance_reports` (v74), `known_devices.device_type`/`seen_count` (v75/v76),
  session-risk history (v77), recording retention policies (v78), `oauth_signing_keys` (v79),
  enrolled-agent ↔ known-device link (v80).

## [1.24.11] - 2026-07-09

### Changed

- **tailwind-merge 2→3** (#54, flagged dependabot runtime major) — used only via the default
  `twMerge(clsx(...))` `cn()` helper, so v3's custom-config breaking changes don't apply. Validated by
  `vite build`, eslint, and 730 vitest tests; admin-console dist rebuilt + deployed.

## [1.24.10] - 2026-07-09

### Changed

- **Frontend build/type tooling majors** — `@types/node` 22→25, `globals` 15→17, `@vitejs/plugin-react`
  4→5 (from the flagged dependabot backlog). `tsc`+`vite build` clean, `eslint` 0 errors; admin-console
  dist rebuilt + deployed. `eslint` 9→10 is **deferred** — the eslint-10 ecosystem isn't ready
  (`eslint-plugin-react-hooks` peer-requires eslint≤9; eslint 10 drops bundled `@eslint/js`).

## [1.24.9] - 2026-07-09

### Fixed

- **SSO audit events now counted in compliance reports & statistics** (#392) — the OIDC SSO audit
  events added in v1.24.7/v1.24.8 used `event_type=sso.login` (with `category=authentication`),
  backwards from the platform convention where authentication events use `event_type=authentication`
  and the compliance/statistics queries filter on it. As a result SSO activity was excluded from
  compliance reports and failed-auth stats. Normalized all OIDC SSO events to
  `event_type=authentication`, `category=sso` (the `sso.*` descriptor is retained as the `action`,
  e.g. `sso_login`, `sso_user_provisioned`), so SSO logins/failures are counted like every other
  authentication event.

## [1.24.8] - 2026-07-09

### Added

- **Failed-login audit for SSO/SAML** (#388, #389) — the OIDC callback and SAML IdP SSO handler
  now emit `outcome=failure` audit events at every failure exit (OIDC: invalid_state,
  token_exchange_failed, id_token_verification_failed, missing_email_claim, provisioning_failed;
  SAML: invalid_authn_request, unknown_service_provider, acs_url_mismatch, sp_disabled,
  response_build_failed). This surfaces attacks/misconfiguration (forged tokens, unregistered-SP
  probing, ACS-URL tampering) in the audit trail, complementing the success events from v1.24.7.
- **Audit events queryable by target** (#390) — `GET /api/v1/audit/events` now honours a
  `target_id` filter (the `AuditQuery.TargetID` field was previously unused), so auditors can scope
  the trail to everything affecting a specific user or resource.

### Changed

- **Dependency bumps** (#386, #387) — `go.uber.org/zap` 1.27→1.28, `pquerna/otp` 1.4→1.5,
  `spf13/viper` 1.18→1.21; frontend `autoprefixer`, `lucide-react`, `eslint-plugin-react-refresh`.
  Part of clearing the dependabot backlog (superseded/stale PRs closed; major bumps flagged for review).

## [1.24.7] - 2026-07-09

### Added

- **SSO/OAuth audit events are now persisted** (#384) — the oauth service's `logAuditEvent`
  previously logged only to the application log, so SSO/OAuth/SAML activity (logins, logouts,
  single-logout, JIT provisioning) never reached the `audit_events` table and was absent from the
  audit query API (`GET /api/v1/audit/events`) and compliance reports. It now persists to
  `audit_events` (async, org-scoped, best-effort — never blocks or fails the request), matching the
  identity service's pattern; the application log is retained.
- **SSO JIT lifecycle audit trail** (#384) — the OIDC callback now emits `sso.user.provisioned`,
  `sso.identity.linked`, `sso.identity.matched`, `sso.identity.backfilled`, and `sso.login`,
  giving a queryable record of how SSO accounts are provisioned, federated-linked, and
  authenticated (builds on the federated-identity work in v1.24.4–v1.24.6).

## [1.24.6] - 2026-07-08

### Changed

- **Backfill the federated identity link for email-matched JIT users** (#369) — completes the
  #364/#367 migration: when a returning OIDC user is matched by email (created before the
  `idp_id`/`external_user_id` binding existed), the login handler now best-effort backfills those
  columns (only when currently unset), so subsequent logins match by `(idp_id, sub)`. Keyed by the
  matched `users.id`; nil-guarded and error-logged, never affects login.

## [1.24.5] - 2026-07-08

### Changed

- **OIDC JIT provisioning matches returning users by IdP subject before email** (#367) — the login
  handler now looks an existing user up by `(idp_id, sub)` first (explicitly org-scoped), falling
  back to email, then creating. A federated user whose email changed at the IdP is no longer treated
  as new (which would have created a duplicate colliding with the unique `(idp_id, external_user_id)`
  index #364 populates). Additive: any lookup miss/error falls through to the prior email path, so
  existing behavior is preserved.

## [1.24.4] - 2026-07-08

### Security

- **Go toolchain → go1.25.12** (#363) — the pinned `toolchain go1.25.11` forced builds onto a
  `crypto/tls` affected by **GO-2026-5856**, failing the govulncheck gate and shipping the vulnerable
  TLS stack in binaries. Bumped to go1.25.12 (govulncheck clean).
- **SAML SLO session-cookie cleared with `Secure` in production** (#362) — `clearIdPSession` cleared
  `openidx_session` with `Secure=false` unconditionally; now tied to `IsProduction()` (matching the
  proxy session-cookie convention), so the deletion still clears over plain HTTP in dev while carrying
  `Secure` in production. Clears `go/cookie-secure-not-set`.

### Fixed

- **Capture `Close` errors on writable files** (#361) — three writable-file writers
  (session-recording append, append-only store, shell-completion install) deferred a bare `Close()`,
  discarding the error; for a writable handle the final flush can surface only at `Close`, so this
  silently dropped data. Each now propagates the `Close` error. Clears `go/unhandled-writable-file-close`.
- **Bind JIT-provisioned users to the IdP subject** (#364) — the OIDC login handler captured the ID
  token `sub` but discarded it, leaving `users.idp_id`/`external_user_id` unpopulated. It now persists
  the federated link on JIT create (best-effort, RLS-scoped). Resolves the dropped-value
  `go/useless-assignment-to-field` on `claims.Sub`.
- **Drop dead `entry.Error` assignment in the request logger** (#365) — the access logger emits via
  `logFields`, not by marshalling the entry, so the assignment was never read; the error is still
  logged. Clears `go/useless-assignment-to-field`.

## [1.24.3] - 2026-07-08

### Fixed

- **Out-of-bounds read in `User.GetFormattedName`** (#359) — the method returned
  `parts[0] + " " + parts[1]` whenever any name component was present, but `parts` holds only one
  element when a user has only a given name or only a family name, so `parts[1]` panicked with an
  index-out-of-range. Now joins the collected parts, which is correct for one or two components.
  Clears the repo's only `error`-severity CodeQL alert (`go/index-out-of-bounds`).

## [1.24.2] - 2026-07-08

### Security

- **Audit report export filename built from allowlisted constants** (#357) — the export file name
  was assembled from the raw request `report_type`/`format` strings, so CodeQL traced
  caller-controlled data to `os.Stat`/`os.Create` even behind the `filepath.Base` + `reportDir`-prefix
  guards it doesn't model. Both fields are already validated against fixed enums; the name is now
  built from a compile-time-constant `typeSlug`/`ext` chosen inside those switches (plus the
  server-generated ID and timestamp), so no request string reaches `filepath.*`. Closes the last
  three `go/path-injection` alerts as fixed — the repo is now at **0 open critical and 0 open high**
  CodeQL alerts. The `reportFilePath` clean+prefix guard remains as defense-in-depth.

## [1.24.1] - 2026-07-08

### Security

- **Audit report export path containment proven to static analysis** (#355) — `reportFilePath`
  already constrained the export file to a single element under `reportDir` via `filepath.Base`
  (#349), but CodeQL does not model `Base`-through-`Join` as a path-injection barrier, so the
  `os.Stat`/`os.Create` sinks stayed flagged. Added an explicit `filepath.Clean` + `reportDir`-prefix
  check (returning an error the caller handles) so containment is provable to static analysis,
  closing the three `go/path-injection` alerts as fixed. With this and the ziti request-forgery
  findings confirmed as trusted-config false positives, the repo is at **0 open critical and
  0 open high** CodeQL alerts.

## [1.24.0] - 2026-07-08

### Security

- **CodeQL critical + high remediation complete.** This release closes the backup-encryption weak-KDF
  (#353) and caps a sweep that brought the repo to **0 open critical and 0 open high** CodeQL alerts —
  via real fixes across v1.23.1–v1.23.5 (integer-overflow env parsing, Ziti management-API SSRF hardening,
  OAuth logout/session JWT signature verification, audit report path-injection, hardware-token secret
  encryption at rest) plus documented false-positive dismissals (HIBP SHA-1 k-anonymity, MySQL DDL,
  trusted-config Ziti base URL, e2e-test regex/randomness, helm empty-password placeholders, dev-profiler
  cert-check) and the structured-`zap`-field log-injection class.
- **Backup encryption KDF → scrypt** (#353) — `internal/backup` derived its AES-256 key from a raw
  `sha256(passphrase)`; it now uses `scrypt` (N=1<<15, r=8, p=1) over a random salt in a versioned,
  magic-prefixed format, with a legacy `sha256` fallback so existing encrypted backups still decrypt.
  Removed the dead `EncryptPassword` helper.

## [1.23.5] - 2026-07-08

### Fixed

- **Hardware-token secrets encrypted at rest** (#351, security) — the hardware-token (YubiKey OATH-HOTP)
  handler stored the TOTP/HOTP seed as `hex(sha256(secret)) + ":" + secret`, i.e. the seed was
  recoverable in plaintext (the hash prefix was security-theater). It's now encrypted with the identity
  service's AES-256-GCM `secretcrypt` cipher (the KEK-backed cipher already used for IdP client secrets);
  decrypt reads both the new `encv1:` format and the legacy format, so existing rows keep working and
  upgrade on the next write. Clears `go/weak-sensitive-data-hashing` (high).

## [1.23.4] - 2026-07-08

### Fixed

- **Audit report export path-injection** (#349, security) — the compliance report exporter built its
  output file path from the request-controlled `report_type`/`format` (`filepath.Join(reportDir, fileName)`)
  with no sanitization, so a `report_type`/`format` containing `../` could write/stat a file outside the
  report directory. Now routed through `reportFilePath()`, which applies `filepath.Base` to constrain the
  name to a single element under `reportDir`. Clears `go/path-injection` (high ×3).

## [1.23.3] - 2026-07-08

### Fixed

- **Ziti management-API request hardening + dependency security bump** (#347) — the generic Ziti
  `mgmtRequest` helper now builds requests through the validated `mgmtURL()` (parses `ZitiCtrlURL`,
  pins scheme+host) instead of raw string concatenation, so a malformed/hostile controller URL cannot
  redirect management calls. Also bumps the indirect `quic-go` dependency v0.59.0→v0.59.1 to resolve
  `GO-2026-5676` (govulncheck). The residual `go/request-forgery` findings on this helper are documented
  false positives (the host is pinned; the appended path holds only internal Ziti resource IDs).

## [1.23.2] - 2026-07-07

### Fixed

- **JWT signature verification on OAuth logout/session endpoints** (#345, security) — `handleLogoutAll`,
  `handleSessionInfo`, and `handleLogout` (end-session) parsed the caller's JWT with `ParseUnverified`
  and acted on the unverified `sub`, so a forged/unsigned token could revoke another user's sessions or
  read their session info. Added `parseVerifiedClaims` (RS256-pinned signature check against the service
  key, alg-confusion-proof, with an expiry-tolerant mode for the OIDC `id_token_hint`) and routed all
  parse sites through it; logout-all/session-info now return 401 on an unverified token, and end-session
  no longer acts on an unverified subject. Clears `go/missing-jwt-signature-check` (high ×3).

## [1.23.1] - 2026-07-07

### Fixed

- **CodeQL critical/high remediation** (#343) — (a) `database.go envInt32` now uses
  `strconv.ParseInt(s, 10, 32)` instead of `int32(strconv.Atoi(...))`, fixing a silent integer-overflow
  truncation of pool-sizing env vars (go/incorrect-integer-conversion ×2); (b) the Ziti management-API
  calls route through a new `mgmtURL()` helper that parses + validates `ZitiCtrlURL` (scheme/host) and
  the response-derived identity ID is `url.PathEscape`'d, clearing the server-side request-forgery
  vectors (go/request-forgery). The MySQL `ALTER USER` DDL (which cannot bind identifiers/passwords and
  is charset-validated + escaped) and the Ziti call against the trusted operator-configured controller
  base URL are documented false positives. No runtime behavior change.

## [1.23.0] - 2026-07-07

### Changed

- **Admin console code-splitting follow-ups** (#341) — `lucide-react` and `@tanstack` now build into
  their own cacheable chunks (`icons`, `query`; the `vendor` chunk drops ~1,176→1,071 kB), and the
  `Layout` outlet is wrapped in its own `<Suspense>` so navigating to an unvisited page spins only the
  content area (the sidebar/header stay rendered) instead of a full-screen fallback. Frontend-only.

## [1.22.0] - 2026-07-07

### Added

- **GCP service-account key rotation connector** (#339) — a new `gcp_sa` PAM rotation connector that
  rotates a Google Cloud service-account key, completing the cloud-IAM rotation pair (AWS shipped in
  v1.21.0). It reuses the engine `Minter`/`PostRotateCleaner` seam: `Mint` creates a new key via the IAM
  API (deleting the oldest USER_MANAGED key first if at GCP's 10-key limit) and stores the decoded
  key-file JSON; `Verify` obtains an OAuth token from the new key (retrying for propagation); cleanup
  deletes all USER_MANAGED keys except the newest after promotion. Selectable from the Rotation Policies
  admin page. Config: `service_account_email`, `admin_secret_id` (a vault secret holding an admin SA
  key-file JSON). The target service account must be dedicated to rotation. Google IAM calls sit behind
  a small interface so the connector is covered by mocked-SDK unit tests. Adds `google.golang.org/api`.

## [1.21.1] - 2026-07-07

### Fixed

- **CodeQL `go/unsafe-quoting` (critical) in AD `unicodePwd` encoding** (#337) — `encodePasswordAD`
  built the Active Directory password value by concatenating double quotes around the password
  (`"\"" + password + "\""`) before UTF-16LE encoding. The encoded bytes are sent as a binary LDAP
  attribute in a `ModifyRequest` (never interpolated into a filter/DN/parsed context), so this was not
  exploitable, but the pattern is now rewritten to a single bounded allocation that writes the quote
  code units directly — clearing the alert (and an allocation-size-overflow on the same function) with
  byte-identical output. Added byte-exact and embedded-quote regression tests.

## [1.21.0] - 2026-07-07

### Added

- **AWS IAM access-key rotation connector** (#335) — a new `aws_iam` PAM rotation connector that rotates
  an IAM user's access keys, selectable from the Rotation Policies admin page. Introduces an engine
  "minter" seam (`Minter` + `PostRotateCleaner`) for providers that mint the secret themselves: the
  connector calls `CreateAccessKey`, verifies the new key via STS `GetCallerIdentity` (retrying for IAM
  eventual consistency), and retires the superseded key only after the new one is promoted. AWS calls
  sit behind small interfaces so the connector is covered by mocked-SDK unit tests. Config:
  `target_user`, `admin_secret_id` (a vault secret holding admin AWS creds as
  `{access_key_id, secret_access_key}` JSON), `region`. The target IAM user must be dedicated to
  rotation (cleanup deletes all its access keys except the newest). GCP service-account keys are a
  planned follow-up on the same seam.

## [1.20.0] - 2026-07-07

### Changed

- **Admin console bundle code-splitting** (#333) — the console shipped as a single ~3.4 MB (875 KB
  gzip) JS chunk. Route pages are now lazy-loaded (`React.lazy` + `<Suspense>`) and `node_modules`
  vendors are split into cacheable chunks via vite `manualChunks`. The initial entry chunk drops from
  ~3,394 KB to ~62 KB (17 KB gzip); heavy libs now load only with the page that needs them
  (`swagger-ui-react` → API-docs page, `recharts` → dashboard). Frontend-only, no behavior change
  beyond a brief loading spinner on first visit to a route.

## [1.19.0] - 2026-07-07

### Added

- **Rotation-policies admin UI — SSH / SSH-key / PostgreSQL / MySQL connectors** (#331) — the Rotation
  Policies page can now create policies for all six registered rotators, not just `directory` and
  `generate_only`. The Connector Type dropdown gains **SSH (password)**, **SSH key-pair**,
  **PostgreSQL**, and **MySQL**, each rendering its required config fields (host, port, admin
  credential secret-picker, target user/role, DB name, SSL/TLS, pinned host key, …) driven by a
  declarative field schema that mirrors the backend validators. The SSH/DB rotation connectors shipped
  in v1.14.0 were previously creatable only via `curl`. Frontend-only — no backend or schema change
  (`connector_config` is a free-form map validated server-side by each connector's `ValidateConfig`).

## [1.18.0] - 2026-07-06

### Added

- **Guacamole recording legal-hold — admin console UI** (#329) — the Session History table on the
  Guacamole Sessions page now has per-recording **Place hold** / **Release hold** controls (with a
  reason prompt) and an **On hold** badge, wired to the existing legal-hold endpoints
  (`POST/DELETE /api/v1/access/guacamole/sessions/:id/legal-hold`). Previously those endpoints — which
  exempt a held recording from the retention sweeper — could only be driven by `curl`. The
  `session-history` list endpoint now returns two read-only, org-scoped flags (`recording_available`,
  `on_legal_hold`) so the UI can render the correct state. No schema change (uses the v68
  `guacamole_recording_legal_holds` table shipped in v1.15.0).

## [1.17.0] - 2026-07-06

### Added

- **OpenZiti made easy** (#326) — the Ziti reconciler is now on by default (`ziti_reconciler=true`), the
  dev compose bundles the ZAC console (`ziti_console_url`), the router runs from a version-controlled
  declarative config (`deployments/docker/ziti-router/`) instead of sed/awk-patching at startup, agents
  auto-enroll, and a one-command Ziti quickstart (`scripts/ziti-quickstart.sh` + guided setup page).
- **One-command box deploy script** (#323) — `scripts/deploy-box.sh` automates the release recipe
  (backup → migrate → roll binaries → verify).

### Changed

- **Security hardening** (#324) — access-revocation and privilege checks tightened; OAuth signing keys
  are now **encrypted at rest** (via the prefix-aware `secretcrypt` helper — legacy plaintext keys are
  read transparently and re-encrypted on rotation); SCIM PATCH support extended in provisioning; the
  published default `ziti_admin_password`/`guacamole_admin_password` must be overridden in production
  (new `ValidateProduction` check).
- Dependency bumps: `go-ldap/ldap/v3` 3.4.8→3.4.12 (#325); Docker base images alpine 3.20→3.24 (#262),
  nginx (#93), node (#94). CI now compiles the integration test suite on every build (#73).

## [1.16.1] - 2026-07-06

### Fixed

- **IAM→Ziti revocation sweep failed on a uuid `user_id`** — the deprovision sweep added in v1.16.0
  queried `WHERE zi.user_id != ''` against the uuid column `ziti_identities.user_id`, which forced an
  empty-string→uuid cast and failed the whole query (`22P02`) every poll, so a disabled user's Ziti
  identity was never deleted. Dropped the redundant `!= ''` (`IS NOT NULL` suffices for a uuid column)
  and added a regression test. Released as a hotfix on top of v1.16.0.

## [1.16.0] - 2026-07-05

### Added

- **Guided Ziti Network Setup** — new admin-console page **Network Setup** (`/ziti-setup`) that makes
  the OpenZiti onboarding understandable, visual, and self-explanatory:
  - **Topology strip**: Clients → Edge Routers → Control Plane → Applications with live status dots.
  - **Setup checklist**: ordered steps (controller connection, CA trust, access-proxy identity,
    edge routers, app exposure, user-identity sync, client access) — each with live status, plain
    remediation text, and a deep-link action button.
  - **Install advisor**: which pieces must be installed *for this deployment* — controller, edge
    router (with `--tunneler-enabled` enrollment commands), BrowZer bootstrapper, client tunneler /
    OpenIDX Agent, hop nginx — labeled Required / Needed-for-your-setup / Optional.
  - **Per-route advice**: stored vs *effective* hosting mode (with auto-correct warnings), the full
    next-hop data path (`edge router → hop nginx :port → upstream`), what the client side needs,
    per-mode requirements, and the reconciler's live converge state per route.
  Backend: `GET /api/v1/access/ziti/setup/status` (aggregated checklist/advisor/route payload,
  reusing the reconciler's `effectiveHostingMode` + install-wide hop-port map so the UI explains
  exactly what will happen) and `GET /api/v1/access/ziti/reconciler/status` (per-service converge
  state, previously log-only). `/ziti-network` tabs are now deep-linkable via `?tab=`.

### Fixed

- **Ziti reconciler survives admin-panel reconnects** — the reconciler ran on the provider slot's
  context, so `POST /ziti/connect` (which Swaps the slot and cancels that context) silently killed
  the reconcile loop for good; subsequent route changes were never converged. It now runs on a
  process-lifetime context (no-ops while disconnected), and the connect handler wakes it via
  `Enqueue()` instead of imperatively hosting services alongside it — the reconciler stays the
  sole mutator, eliminating the double-hosting 502 path.
- **`PUT /ziti/settings` validates before persisting** — a malformed/empty controller URL or empty
  admin user is now rejected with 400 instead of being saved silently and only failing at the next
  connect. CI: the Benchmarks job could never post its PR comment (workflow token is read-only) and
  failed after the benchmarks had passed; it now has job-level write permission and degrades to a
  warning when the token can't comment.

### Security

- **Disabled/deleted IAM users are deprovisioned from Ziti** — the user-sync poller now sweeps
  Ziti identities whose user is disabled or gone (controller delete + mirror-row delete, batched,
  retried). Previously a revoked user's enrolled tunneler kept a valid Ziti identity — and network
  access — indefinitely. Infrastructure identities (access-proxy, admin, routers) are untouched.

## [1.15.0] - 2026-07-05

### Added

- **Guacamole recording legal-hold** (#318) — place a legal-hold on a Guacamole session's recording
  so it is never deleted by the retention purger. New `guacamole_recording_legal_holds` table
  (migration **v68**, FK → `guacamole_sessions` with a UNIQUE active-hold index), the recording
  retention sweeper (`sweepExpiredGuacRecordings`) now excludes sessions under an active hold, and
  admin-gated, audited endpoints:
  - `POST   /api/v1/access/guacamole/sessions/:id/legal-hold` (409 if one is already active)
  - `DELETE /api/v1/access/guacamole/sessions/:id/legal-hold`
  - `GET    /api/v1/access/guacamole/sessions/:id/legal-holds`
  Each endpoint verifies the session is visible under the caller's org before acting. Mirrors the
  existing remote-support legal-hold; a testcontainer test proves a held recording survives the
  sweep and is purged once released.

### Upgrade

- Migration **v68** adds a table (additive). Run `cmd/migrate up` (or the compose `migrate` service)
  before/at deploy.

## [1.14.1] - 2026-07-04

### Changed

- **All registered rotation connectors are now creatable via the CreatePolicy API** (#316) —
  `validatePolicyInput` previously accepted only `directory`/`generate_only`, so `ssh`, `postgres`,
  `ssh_key`, and `mysql` rotation policies required a direct DB insert. A new optional
  `ConfigValidator` interface lets each connector validate its own `connector_config` (delegating to
  its existing config parser), and the engine now accepts any **registered** connector type.
  **Note:** the accepted connector-type set is now registration-dependent rather than a hardcoded
  pair; unregistered types are rejected with a clear error.

## [1.14.0] - 2026-07-04

Two new PAM credential-rotation connectors, extending the M5 rotation engine.

### Added

- **SSH key-pair rotation connector** (`ssh_key`) (#313) — rotates a POSIX account's SSH key: the
  stored secret value is a freshly generated ed25519 OpenSSH private key; the derived public key is
  installed into the target's `authorized_keys` (a single tagged line, replaced each rotation) over
  an admin SSH session, and rotation is verified by logging in as the target with the new key. Reuses
  the existing `FixedHostKey` verification. No new dependencies.
- **`ValueGenerator` engine seam** (#313) — an optional interface letting a connector produce the
  secret value itself (e.g. a private key) instead of the engine's default random password. Existing
  connectors are unaffected.
- **MySQL rotation connector** (`mysql`) (#314) — rotates a MySQL user's password via `ALTER USER`,
  authenticating with a bootstrap admin credential from the vault, verified by connecting as the
  target with the new password. New dependency: `github.com/go-sql-driver/mysql`. Because MySQL DDL
  cannot bind the password, the connector strictly validates identifiers, escapes the password as a
  single-quoted literal, and strips `NO_BACKSLASH_ESCAPES` on a pinned connection — verified against
  injection-shaped inputs.

### Notes

- Cloud-IAM (AWS/GCP) rotation is deferred (heavy SDKs, not locally verifiable).
- Follow-up: `validatePolicyInput` accepts only `directory`/`generate_only`, so `ssh`/`postgres`/
  `ssh_key`/`mysql` rotation policies must currently be created out-of-band (pre-existing gap).

## [1.13.1] - 2026-07-04

### Fixed

- **Elasticsearch client validates auth at construction** (#311) — `NewElasticsearchFromConfig`'s
  connectivity ping only inspected the transport error, so a wrong/absent password against a
  security-enabled cluster (a 401/403 with `err == nil`) silently "connected" and then failed every
  operation. It now checks `res.IsError()` and returns a clear error, so bad ES credentials surface at
  startup. Audit-service still treats Elasticsearch as best-effort (warn + continue), so this turns a
  silent operation-time failure into a clear startup warning. Surfaced by the v1.13.0 ES-auth smoke test.

## [1.13.0] - 2026-07-04

Elasticsearch authentication for the docker-compose deploy path — the last deferred item from
the prod-compose hardening bundle. Compose-only; the app-side ES auth was already built.

### Changed

- **Elasticsearch security enabled in prod compose** (#309) — `docker-compose.prod.yml` sets
  `xpack.security.enabled=true` + `xpack.security.http.ssl.enabled=false` + `ELASTIC_PASSWORD` on
  the `elasticsearch` service (HTTP basic auth over the private network), and wires
  `ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD` into `audit-service` (the only ES consumer,
  which already passes them to the auth-aware client). Dev/infra compose keep security disabled.
- **`ValidateProduction` requires ES credentials** (#309) — when `APP_ENV=production` and
  `elasticsearch_url` is set, `elasticsearch_username`/`elasticsearch_password` must be provided
  (conditional, so ES-unused deployments are unaffected).

### Notes

- Baseline is HTTP basic auth; self-signed ES HTTP TLS (parity with the v1.12.0 Postgres TLS) is a
  documented follow-up. Dedicated least-privilege ES roles are also a follow-up (uses the built-in
  `elastic` user for now).
- Upgrade: set `ELASTIC_PASSWORD` and a matching `ELASTICSEARCH_PASSWORD` in `.env` before a prod
  `docker compose up`.

## [1.12.0] - 2026-07-04

Production-readiness hardening for the docker-compose deploy path. Compose-only —
systemd/managed deployments are unaffected.

### Added

- **Startup readiness probes** (#307) — `internal/common/health.WaitForDependency` (bounded
  retry) plus `ProbeHTTP`/`ProbeOPA`. Services now verify hard dependencies at boot instead of
  returning 500s later: the OPA-using services (admin-api, provisioning, governance) probe
  `OPA/health` and the access service probes its Ziti controller — **fail-fast in production,
  warn and continue in development**. The OPA probe is gated on `EnableOPAAuthz` so a deploy
  that doesn't use OPA never blocks on it; APISIX is intentionally not probed (its reconciler
  already self-heals).
- **Self-signed Postgres TLS in prod compose** (#306) — a `pg-certgen` one-shot service
  generates a server cert (owned uid 70, key mode 0600) into a `pg_certs` volume; the prod
  Postgres runs with `ssl=on`, and the app/migrate/seed DSNs default to
  `sslmode=${DATABASE_SSL_MODE:-require}` so DB traffic is encrypted out of the box. Point at an
  external managed Postgres by setting `DATABASE_SSL_MODE` and supplying your own certs.

### Changed

- **DB pool sizing is configurable** (#306) — `DB_MAX_CONNS`/`DB_MIN_CONNS` (defaults 25/5)
  replace the hardcoded pool limits in `internal/common/database`.
- **APISIX admin key sourced from `APISIX_ADMIN_KEY`** (#306) via native APISIX `${{...}}` env
  substitution (no more `CHANGE_ME_ADMIN_KEY` in the config), wired into all three compose files;
  `admin_allow_ip` tightened to loopback + the container bridge ranges (`10.0.0.0/8`,
  `172.16.0.0/12`).
- **Graceful-shutdown timeout is configurable** (#306) — `SHUTDOWN_TIMEOUT_SECONDS` (default 30)
  replaces the hardcoded 30s across all services.

### Notes

- Elasticsearch `xpack.security` remains deferred (needs ES-client auth wiring).
- Upgrade: the `openidx_app` password hook and now Postgres TLS certs are generated on **first
  init of a fresh `postgres_data` volume**; existing volumes need the operator to provision them
  once (see the v1.11.0 note for the role password).

## [1.11.0] - 2026-07-04

Docker-compose deployments are now tenant-isolated. Previously a fresh
`docker compose up` was pre-multi-tenancy at the schema level (`init-db.sql` had no
RLS belt and app services connected as the `openidx` superuser, which bypasses RLS
entirely). This release makes migrations the sole schema source in compose and cuts
the app services over to the non-owner `openidx_app` role so the FORCE'd RLS
policies enforce — matching the box and managed/RDS deployments.

### Added

- **`migrate` + `seed` one-shot compose services** (#303) — a `migrate` service builds
  the full v1–v67 schema (as the superuser) after Postgres is healthy, then a `seed`
  service applies the functional-delta bootstrap. App services gate on the seed
  completing (`depends_on: service_completed_successfully`). Wired into
  `docker-compose.yml`, `docker-compose.prod.yml`, and `docker-compose.infra.yml`.
- **`deployments/docker/bootstrap.sql`** (#303) — minimal first-init (the passwordless
  `openidx_app` role + `GRANT CONNECT`); migrations own everything else.
- **`deployments/docker/seed.sql`** (#303) — idempotent functional-delta bootstrap
  (`role_permissions` + default risk/posture/privacy/notification/lifecycle/ispm
  policies + tenant branding), org-scoped, applied under `app.bypass_rls`.
- **`deployments/docker/set-app-role-password.sh`** (#304) — first-init hook that sets
  the `openidx_app` password from `OPENIDX_APP_PASSWORD` (sorts after `bootstrap.sql`).
- **`test/integration/compose_seed_test.go`** (#303) — e2e guard: migrate-from-empty →
  `seed.sql` → asserts the login bootstrap and that RLS fails closed for a NOSUPERUSER
  role without an org GUC and returns default-org rows with one set.

### Changed

- **Compose app services connect as `openidx_app`** (NOSUPERUSER, NOBYPASSRLS) (#304),
  so the v37 FORCE-RLS policies enforce. `migrate`/`seed` stay on the `openidx`
  superuser (they own DDL + seed). Add `OPENIDX_APP_PASSWORD` to the postgres env and
  `.env` / `.env.production`.
- **`scripts/seed.sh`** now re-applies `seed.sql` (migrations own the schema + login
  bootstrap) instead of the removed `init-db.sql`.

### Removed

- **`deployments/docker/init-db.sql`** — retired as the schema source. Layering
  migrations on top of it was permanently blocked (v29 `ziti_certificates(identity_id)`
  ordering), and the file was itself broken on current Postgres (`NOW()` in a
  partial-index predicate). Migrate-from-empty is clean to v67 and already seeds a
  working admin install (default org, admin user, `admin-console` client, roles).
- **`TestInitDBParity` / `TestInitDBColumnParity`** (`internal/migrations/initdb_parity_test.go`)
  — no subject once `init-db.sql` is gone; migrations are the sole schema source.

### Upgrade note

The `openidx_app` password hook runs only on **first init of a fresh `postgres_data`
volume**. On an **existing** volume, set the password once:
`ALTER ROLE openidx_app WITH LOGIN PASSWORD '<OPENIDX_APP_PASSWORD>';` (or
`docker compose down -v` / `make dev-clean` to recreate the volume). This is a
compose-only change — systemd/managed deployments are unaffected.

## [1.10.1] - 2026-07-04

Encrypt-secrets-at-rest hardening pass. Secret columns that were previously stored as plaintext
are now AES-256-GCM encrypted at rest, keyed by `ENCRYPTION_KEY`. Rollout is lazy and
flag-day-free: reads are prefix-aware (tagged ciphertext is decrypted; legacy plaintext passes
through untouched), and environments without a usable key fall back to a warned passthrough rather
than crashing.

### Added

- **`internal/common/secretcrypt`** — shared AES-256-GCM helper (#298). `Encrypt` emits
  `encv1:<base64(nonce‖ciphertext)>`; `Decrypt` is prefix-aware (tagged → decrypt, untagged legacy
  plaintext → passthrough); `NewNoop()` provides a best-effort passthrough cipher for environments
  without a 32-byte key (services warn and continue rather than fail closed).

### Changed

- **Webhook signing secrets encrypted at rest** (#299) — `webhook_subscriptions.secret` is now
  encrypted on create and decrypted on read and before HMAC signature computation. Column widened to
  `TEXT` (migration **v65**; file-based `202607030001`).
- **Identity-provider client secrets encrypted at rest** (#300) — `identity_providers.client_secret`
  is encrypted on create/update and decrypted on every read path: identity get/list, the access
  service's multi-IdP route resolution, and the OAuth social-login token exchange. Column widened to
  `TEXT` (migration **v66**; file-based `202607030002`).
- **Guacamole pool tokens encrypted at rest** (#301) — `guacamole_connection_pool.token` is encrypted
  on write. The column is write-only (the in-memory pool serves reads), so there is no decrypt path — a
  database dump cannot yield usable session tokens. Column widened to `TEXT` (migration **v67**).

### Notes

- `oauth_clients.client_secret` was already SHA-256 hashed (constant-time compare, never re-returned)
  and is intentionally out of scope for this pass; the stale `-- TODO: Encrypt` marker was removed.
- Highest migration is now **v67**. `init-db.sql` defines all three columns as `TEXT` directly, so
  fresh installs need no backfill.

## [1.10.0] - 2026-07-03

Readiness-finalization pass across three workstreams: make the shipped PAM usable from the
admin console (W1), close correctness/tenant-isolation gaps (W2), and light production
hardening (W3).

### Added
- **PAM admin console** — the previously backend-only PAM surface is now driveable from the
  console: **Vault Secrets** page (list/create/versions/grants + reason-gated one-shot reveal +
  checkout ledger; #284), **Rotation Policies** page + per-secret rotate-now/history (#285),
  **Privileged Sessions** page (Guacamole pending-request approve/deny, active-session
  monitor/share/force-terminate, transcript download; #286), and a **`vault_credential`** option
  in Access Requests with one-shot retrieve + return-early (#287). A "Privileged Access" nav
  group + dashboard entry point (#289).
- **`GET /api/v1/access/guacamole/session-history`** — admin-guarded, org-scoped listing of
  Guacamole session rows with a `transcript_available` flag (no file paths), so transcripts are
  reachable from the console. (#286)
- **`GET /api/v1/vault/secrets/:id/grants`** — list a secret's access grants (metadata only). (#284)
- **OpenAPI specs** for all shipped PAM endpoints (vault, rotation, Guacamole sessions,
  `vault_credential` retrieve/return) across the admin-api/access/governance specs. (#288)
- **Column-level init-db↔migrations parity guard** (`TestInitDBColumnParity`) — fails CI when an
  `init-db.sql` column is created by no migration (the drift class that breaks migrate-only
  RDS/Helm installs). (#292)

### Changed / Security
- **Attestation tenant isolation** — `attestation_campaigns`/`attestation_items` (created by v54
  without `org_id`) gained `org_id` + the v37 FORCE-RLS belt (USING + WITH CHECK); handlers tag
  `org_id` on write and rely on RLS for reads. Closes a cross-org read/write exposure. Migration
  v61. (#290)
- **`org_id` + FORCE-RLS belt** added to `jit_grants` and `request_approval_chains` (previously
  org-scoped only in-handler). Migration v64. (#293)
- **Access-proxy idle timeout enforced** — routes' `idle_timeout` was dead config on the data
  plane (only absolute expiry was checked). The proxy + forward-auth paths now revoke and re-auth
  a cookie session idle beyond `idle_timeout` (sliding window; bearer tokens unaffected). (#294)
- **Production requires an explicit vault KEK** — `ValidateProduction` now fails unless `VAULT_KEK`
  or `VAULT_KEKS` is set, instead of silently falling back to `ENCRYPTION_KEY` for the vault
  key-encryption key. (#295)

### Fixed
- **Referenced-but-uncreated tables reconciled** — `admin_console_settings`, `auth_contexts`,
  `breach_incidents`, `breach_alerts` were referenced by code but created by neither a migration
  nor `init-db.sql` (latent 500s, the `jit_grants`-class drift). Migration v62 creates them.
  (`access_stats`, also flagged, was a false positive — a CTE, not a table.) (#291)
- **`ziti_certificates` column drift** — the migration schema had diverged wholesale from the
  code/init-db schema (`cert_data NOT NULL`, … vs `cert_type`/`not_after`/`status`/…), breaking
  cert-hardening on migrate-only installs. Reconciled to the code schema; also reconciled 8 other
  tables whose init-db `ALTER … ADD COLUMN` patches were never mirrored into a migration.
  Migration v63. (#292)

### Notes
- **OPA fail-open** was verified to be unreachable in production (the middleware's `devMode` is
  `cfg.IsDevelopment()`, false in prod → fails closed with 403); a regression test now pins the
  invariant. No code change to `opa.go`. (#295)
- **Deferred follow-ups** (tracked; not implemented):
  - **MySQL and cloud-IAM (AWS/GCP/Azure) rotation connectors** behind the M5 `Rotator`
    interface (v1.9.1 shipped SSH + PostgreSQL); **SSH *key* rotation** (v1.9.1 shipped SSH
    *password* rotation).
  - **Guacamole recording legal-hold** — retention works, but `recording_legal_holds` is FK'd to
    `remote_support_sessions` only; covering `guacamole_sessions` recordings needs a shared-hold refactor.
  - **Multi-tenant / production-GA hardening**: docker-compose `openidx_app` (non-owner) cutover +
    FORCE-RLS for compose; prod-compose TLS/Elasticsearch-security/APISIX-admin-key hardening;
    encrypt-at-rest for the legacy plaintext secret columns (`oauth_clients.client_secret`,
    `identity_providers.client_secret`, webhook secrets, guac pool token) via the vault; rotate the
    git-history-compromised APISIX admin key.

## [1.9.1] - 2026-07-02

PAM session assurance (M4) + rotation connectors (M5), plus a recording
data-loss fix.

### Added
- **Session transcripts** — a `guaclog`-based sweep generates a keystroke/command
  transcript for ended/terminated recorded Guacamole sessions and serves it via an
  admin-guarded `GET /api/v1/access/guacamole/sessions/:id/transcript`. Generation is
  `exec.LookPath`-gated (inert if `guaclog` is absent); `guaclog` is included in the
  access-service image. (#279)
- **Live session monitor** — `POST /api/v1/access/guacamole/sessions/:id/share` mints a
  read-only Guacamole connection-sharing link (falls back to the active-session list when
  the server lacks the sharing API). (#279)
- **Session-end detection** — a background sweep reconciles tracked sessions against
  Guacamole's active connections and marks naturally-ended sessions (2-minute grace;
  fail-safe when Guacamole is unreachable). (#279)
- **Attestation of privileged entitlements** — new `vault_access` and `rotation_policy`
  access-certification campaign types; a revoke decision deletes the vault grant / disables
  the rotation policy. (#279)
- **SSH + PostgreSQL rotation connectors** — the rotation engine can now rotate credentials
  on Linux/SSH hosts (`chpasswd` over SSH, host-key-pinned, password via stdin) and
  PostgreSQL (`ALTER ROLE` with server-side identifier/literal quoting). Each resolves its
  bootstrap/admin credential from the vault and verifies by authenticating with the new
  credential; both fail closed. No new dependencies. (#280)

### Fixed
- **Guacamole recording data loss** — `guacamole_sessions.recording_path` stored the shared
  recordings *directory*, so the retention sweep's `RemoveAll` could delete every recording.
  The full recording *file* path is now persisted and purge is guarded so it can never
  remove the recordings root. (#279)

## [1.9.0] - 2026-07-02

Privileged Access Management (PAM) — an integrated credential vault, automated
rotation, just-in-time credential checkout, and privileged-session brokering with
server-side credential injection. Built on the existing vault crypto, approval
workflows, Guacamole brokering, and recording/retention pipeline.

### Added
- **Credential vault** — tenant-isolated, envelope-encrypted secret store
  (per-version HKDF + AES-256-GCM under a rotatable key-encryption keyring that
  defaults to `ENCRYPTION_KEY`; fail-closed). Versioned secrets, per-secret access
  grants, internal server-side `use` vs. reason-gated + audited `reveal`;
  admin-guarded `/api/v1/vault/*` API. Migration v56. (#273)
- **Automated credential rotation** — leader-gated rotation engine with pluggable
  connectors (Active Directory / LDAP / Azure AD via directory write-back;
  generate-only). Candidate-version → apply-to-target → verify → promote, so a
  failed rotation never locks the account out. Scheduled, on-demand (admin), and
  rotate-on-checkout triggers. Migration v57. (#274)
- **Just-in-time credential checkout** — request a vault credential through the
  existing multi-step approval workflow (`resource_type=vault_credential`); on
  approval the requester retrieves the secret once for a bounded window, after
  which access auto-revokes and the credential rotates. (#276)
- **Privileged session brokering with credential injection** — Guacamole
  RDP/SSH/VNC sessions inject the target credential from the vault **server-side**
  (the browser never receives it), with an optional pre-session approval gate,
  admin force-terminate (with reason), and native session recording retained via
  the existing recording-retention policy. Migration v59. (#277)

### Fixed
- Created `jit_grants` and `request_approval_chains` — referenced by governance
  code but never created by any migration, so JIT elevation, the escalation
  worker, and `POST /api/v1/governance/requests` were returning 500s. Migration
  v58. (#275)

### Notes
- Each service that uses the vault (admin-api, governance, access) reads the shared
  `ENCRYPTION_KEY` / `VAULT_KEK` and instantiates an in-process vault; the access
  service additionally needs a shared recording volume for Guacamole recordings.

## [1.8.2] - 2026-07-01

### Added
- **Optional device-trust enforcement for clientless (BrowZer) access.** With
  `OPENIDX_REQUIRE_DEVICE_TRUST_FOR_CLIENTLESS=true` (off by default), an OIDC
  login for the clientless (BrowZer) client from an untrusted device is refused —
  the login page shows "This device must be approved before clientless access" and
  a device-trust request is filed for admin approval (admin console → **Device
  Trust Approval**); after approval, the retry succeeds. Closes the gap where a
  BrowZer route's `require_device_trust` was silently unenforced (BrowZer traffic
  bypasses the proxy's HTTP forward-auth). Enforced at the OIDC login
  (`handleAuthorizeCallback` — BrowZer's server-rendered login — and
  `handleLogin`); per-device, not per-route. (#268, #269, #270)

## [1.8.1] - 2026-07-01

Security & production-readiness hardening — remediation of the v2.0 GA
production-readiness audit (all P0s + four P1s + a P2 cluster).

### Security
- Access proxy now verifies a bearer JWT's signature + expiry (RS256 via the
  OAuth JWKS) before building a session; forged/unsigned tokens are rejected
  (P0-1, #255).
- Pre-tenant-resolution lookups against RLS-forced tables (API-key validation,
  proxy route/session/device/posture reads, Ziti startup, audit webhook
  bookkeeping) are bypass-wrapped so they no longer fail closed under the
  non-owner `openidx_app` role; WebAuthn login is org-scoped (P0-2, #254).
- OAuth token introspection now honors revocation — a revoked token reports
  `active:false` (#259).
- Removed the hardcoded APISIX admin key from the repo; templated from env
  (P0-4, #256). **Rotate the previously-committed key wherever deployed.**
- Enabled branch protection on `main` (Required Checks, enforce_admins) (P0-5).
- Production config validation now checks the *effective* DB sslmode (parsed from
  `DATABASE_URL`, not just the standalone field) (#263).
- Bumped auth/transport-critical dependencies (x/crypto, x/net, pgx/v5,
  go-webauthn, go-redis/v9); transitive advisories dropped 23→2 (#264).
- Platform-admin cross-org audit now records under RLS and logs failures;
  IP-threat DB errors are surfaced; dead runtime-DDL removed (P2, #265).

### Fixed
- 58 tables that existed only in `init-db.sql` are now created by migration
  **v54**, so managed-Postgres/RDS/Helm/`migrate` installs stop 500ing across
  MFA/SAML/social/lifecycle/ISPM/audit features; a parity test guards against
  recurrence (P0-3, #257).
- Split the deprovisioning policy-run log into `lifecycle_policy_executions`
  (migration **v55**) — it collided with the workflow `lifecycle_executions`
  schema, breaking deprovisioning execution records on every install (#258).
- Docs workflow no longer passes `latest latest` to `mike deploy` (#261).

### Changed
- Migrated off go-redis deprecated APIs (`SetEx`→`Set`, `GetSet`→`SetArgs`,
  `ZRevRange`→`ZRangeArgs`) (#264).
- `.gitignore` now excludes `*.zip` to prevent stray archive exports being
  committed (#266).

## [1.8.0] - 2026-06-29

### Added
- **Database-enforced tenant isolation (RLS activation)** — the v1.8 milestone of
  the multi-tenancy epic. The app now connects as a dedicated non-owner
  `openidx_app` role (`NOSUPERUSER NOBYPASSRLS`), so the `FORCE`'d row-level
  security policies (the predicate + FORCE shipped earlier in v37) finally
  enforce instead of being bypassed by a superuser connection. A no-GUC query on
  a scoped table now returns 0 rows; queries see only the request's org via the
  `app.org_id` GUC set at pool checkout; platform/cross-org paths opt in via
  `app.bypass_rls`. This is defense-in-depth *behind* the v1.7 app-layer `org_id`
  filtering. (#250)

### Changed
- **Migration v53** provisions `openidx_app` with blanket DML grants + default
  privileges (passwordless; the password is set out-of-band at deploy). Migrations
  and DDL continue to run as the owner role; services keep `AUTO_MIGRATE` off and
  the app `DATABASE_URL` points at `openidx_app`. `init-db.sql` provisions the
  same role for fresh installs. (#250)

## [1.7.2] - 2026-06-29

### Security
- **`github.com/jackc/pgx/v5` v5.5.4 → v5.9.2** — resolves GO-2026-5004.
  `govulncheck` now reports 0 affected vulnerabilities. (#248)

### Fixed
- **CI hard gates restored to green** (`Required Checks`). The org-scope, lint,
  and vulnerability gates had regressed:
  - **orgscope**: annotated the 19 org-unscoped queries the governance/devices
    work introduced (the Relations & Integrity Doctor's whole-install scans and
    queries keyed by globally-unique ids) with reviewed `//orgscope:ignore`
    directives. (#247)
  - **lint**: removed an unused var + orphaned import in `ziti_settings.go`;
    justified the deprecated, operator-supplied `google.CredentialsFromJSON` call
    in `play_integrity.go`; migrated the RLS pool hook `BeforeAcquire →
    PrepareConn` (deprecated by the pgx bump), preserving exact checkout
    semantics. (#247, #248)

## [1.7.1] - 2026-06-26

### Fixed
- **A fresh `apisix-edge` install can now stand up the full eight-service stack
  from a clean checkout.** The `gateway` service (`:8008`) is tracked as a
  systemd unit and added to the install's `enable --now` list (it had been
  running as an unmanaged `/tmp` process); the runbook now builds the service
  binaries into `~/oidx-runtime/bin` (the units' `ExecStart` targets); and the
  access-service launch wrapper ships as a sanitized `run-access.sh.example`
  (previously untracked, so a fresh install left the access-proxy with no start
  script). (#243, #244, #245)

## [1.7.0] - 2026-06-26

### Governance & devices: policies that enforce + real device trust (#234–#239)

Made the governance and devices domains actually work end-to-end. The policy
engine was a permissive no-op and device-trust signals were never populated, so
Zero-Trust controls silently passed everything; the device-trust approval
workflow existed but had no entry point; and a redundant policy engine sat
unwired. After this work: governance policies evaluate and enforce, device
posture and per-device trust flow into every access decision (forward-auth and
continuous re-verification), untrusted devices on trust-required routes file
approval requests that flip trust on approval, and the dead engine is gone.

#### Added
- **Device posture bridge** (D1): agent posture reports are written to
  `device_posture_results` so the access context evaluator enforces posture for
  the reporting device; migration v50 adds the upsert key. (#234)
- **Service-to-service auth for policy evaluation** (G1): a shared
  `INTERNAL_SERVICE_TOKEN`; the access-proxy presents it as `X-Internal-Token`
  (constant-time, scoped to governance `/evaluate`) so the policy call is
  authenticated instead of 401-failing-closed. (#235)
- **Device-trust request auto-creation** (D3): when an untrusted device hits a
  `require_device_trust` route, the proxy files a deduped pending
  `device_trust_requests` row — the missing entry point that feeds the existing
  approval queue. Approve/reject now notify the user, and new requests notify
  org admins, via the notifications service. (#238)
- **Migration v52**: reconcile the continuous-verify columns that existed only in
  `init-db.sql` (`proxy_sessions.{last_verified_at,verification_failures,geo_*,
  idp_id,device_trusted}`, `user_sessions.device_trusted`) onto migrate-based
  installs. (#239)

#### Changed
- **The governance policy engine actually enforces** (G1): `GetPolicy` /
  `ListPolicies` now load `policy_rules` (via a shared `loadPolicyRules`), so the
  per-type evaluators (separation-of-duty, risk, timebound, location,
  conditional-access) and the step-up loop run against real rules instead of an
  empty set. (#235)
- **`ProxySession.DeviceTrusted` is populated** from `known_devices.trusted`,
  matched by the request's device fingerprint (D2) — feeding the context checks,
  the inline policy DSL, and the governance `/evaluate` call. The continuous
  verifier re-derives it live each pass rather than reading a stale column.
  (#237, #239)

#### Fixed
- **Policy rule loading queried non-existent columns** (`condition/effect/
  priority` vs the real `rule_type/conditions/actions`); the error was swallowed,
  so rules silently never loaded — the true root cause behind "policies don't
  enforce." (#235)
- **The continuous session verifier errored every run** on migrate-based installs
  — its driver query referenced `proxy_sessions` columns present only in
  `init-db.sql`. (#239)

#### Removed
- **The dead `ZTPolicy` subsystem** (handler, store, model, tests; ~4,900 LOC)
  — never wired into any service, no table, no UI, its general-ABAC niche already
  served by the live `abac-policies` surface. Migration v51 drops the (never
  created) `zt_policies` / `zt_policy_versions` tables as a belt. (#236)

### Relations & Integrity Doctor — cross-domain health + referential integrity (#230, #231, #233)

A self-service "doctor" that scans the relationships *between* domains — proxy
routes, Applications tiles, OAuth clients, Ziti services, published apps,
identities — surfaces broken or orphaned wiring, and heals the safe cases
automatically; plus DB-level referential integrity so the most common orphans
can't form in the first place.

#### Added
- **Relations & Integrity Doctor** (`internal/access/health_engine.go`,
  `health_checks.go`): a check registry that scans cross-domain relations
  (route↔tile, app↔client, route↔Ziti, host uniqueness, published-app,
  identity↔Ziti, BrowZer-config dedup, domain presence, …), returns a structured
  report, auto-heals findings classified Safe, and leaves risky ones for an
  explicit fix. Exposed at `GET /api/v1/access/health/relations[?heal=safe]` and
  `POST /api/v1/access/health/fix/:checkId`, with a `HealRoute` after-mutation
  hook so a route change re-checks its own wiring. (#230)
- **Referential integrity** (migration v49): `applications.route_id →
  proxy_routes` and `applications.oauth_client_id → oauth_clients`, both
  `ON DELETE CASCADE`, backfilled from the existing id conventions — so deleting
  a route or client can no longer strand an Applications tile/app. (#231)

#### Changed
- Doctor check polish from review follow-ups: tightened classifications and
  counts (e.g. domain-presence counts `known_devices`, not a non-existent table).
  (#233)

### App, OAuth & clientless-publishing fixes (#223–#229, #232)

A run of fixes making OAuth client registration, the Applications view, and
clientless app publishing mutually consistent — registered clients are visible
and editable, and a published app maps cleanly to one host / one Ziti service.

#### Added
- **Applications tiles auto-sync for proxy routes**: creating/registering a
  client or proxy route surfaces a launcher tile without a manual step.
  (#224, #225)
- **App redirect_uris auto-register on the BrowZer OIDC client**, so a freshly
  published clientless app doesn't 400 on its first OAuth redirect. (#227)
- **One-app-per-host publishing**: an app publishes as a single host route → one
  Ziti service → one BrowZer target → one APISIX route, instead of exploding into
  one route per discovered path (which collided on the per-host BrowZer naming);
  discovered paths stay as advisory metadata. (#229)

#### Fixed
- **OAuth client registration 500** — new clients weren't assigned a UUID. (#223)
- **Registered clients didn't appear** in the Applications list. (#224)
- **Editing an application** now syncs its backing OAuth client (name/redirects),
  instead of drifting from it. (#226)
- **BrowZer config generators use the *effective* hosting mode** (fixing overlay
  error `1010` when a route's stored mode disagreed with its resolved mode).
  (#228)
- **`ziti_browzer_config` is a singleton** — the bootstrap reseed no longer
  appends a new row on every startup. (#232)

### Clientless edge on APISIX + console-managed publishing (#211–#221)

Moved the public `:443` edge from nginx to **Apache APISIX** as the single TLS
terminator, with the access-service pushing per-app BrowZer routes to it
dynamically; and hardened publishing so a clientless app can be created,
**edited, renamed, and deleted entirely from the admin console** without leaving
orphaned overlay/edge state. Resolves a class of failures hit while publishing
external HTTPS apps (`secops`, `es-dev`): BrowZer `1003`, OAuth/SAML 403s, and
stranded wiring after a rename/delete.

#### Added
- **APISIX edge** (`deployments/apisix-edge/`): a dedicated APISIX instance as
  the sole `:443` edge (TLS via the `*.tdv.org` wildcard), with `seed-edge-routes.sh`
  for the static routes (API fan-out, `/oauth`, `/scim`, `*.tdv.org` access-proxy)
  and systemd user units for the access + backend services. nginx is reduced to
  the admin-console SPA upstream. (#211, #213)
- **APISIX route reconciler** (`internal/access/apisix_reconciler.go`): the
  access-service pushes/prunes the per-app `browzer-<app>` edge routes from
  `proxy_routes` via the Admin API (gated by `APISIX_EDGE_ENABLED`). (#211)
- **Hosting-mode picker** in the proxy-route create/edit form — **Auto
  (recommended) / Hop — external·HTTPS / Direct — local·dark** — wired through the
  proxy-route CRUD (`hosting_mode`). (#220)
- **Edge routes for the oauth-service's management APIs**: `/api/v1/oauth/*` and
  `/api/v1/saml/*` now route to `:8006` (were missing, so they fell to the
  `/api/*` admin catch-all and 404'd). (#218, #219)
- **Router WSS config artifacts** (`deployments/apisix-edge/ziti-router/`): the
  edge router serves the clientless BrowZer overlay on `wss:3023` presenting the
  browser-trusted `*.tdv.org` cert via `transport.wss.identity`. (#214, #215)
- Docs: clientless edge architecture (`docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md`)
  and a publish-a-service guide with the full certificate matrix
  (`docs/PUBLISHING_A_SERVICE.md`). (#212, #217)

#### Changed
- **BrowZer routes auto-select their hosting mode** from the upstream:
  `EffectiveMode` promotes a BrowZer route off `identity` (never valid for the
  `#browzer-users` dial) and picks **hop** for external HTTPS / Host-routed
  upstreams, **direct** for local/HTTP — explicit hop/direct still honored. (#220)
- **OAuth client management and SAML SP management are now always authenticated**,
  not just outside `development` — the management groups get the auth middleware
  unconditionally while the interactive OIDC flow endpoints keep their env-gated
  behavior. (#218, #219)
- The external-IdP **OIDC `form_post` bypass is OFF by default**
  (`BROWZER_OIDC_CALLBACK_PATHS=""`): once the WSS overlay is healthy the service
  worker tunnels the callback, so a direct bypass splits the cookie context and
  loops the app back to login. (#216)

#### Fixed
- **BrowZer `1003` (service not dialable by the overlay)**: the reconciler now
  **converges** Bind/Dial service policies (upsert by name) instead of
  create-if-exists, so a route that transitions identity→router-hosted (e.g.
  BrowZer enabled after OpenZiti) has its stale `#access-proxy-clients` policies
  corrected to `#ziti-routers` / `#browzer-users`. (#220)
- **OAuth/SAML management 403/404 through the edge**: routing gap (mis-routed to
  admin-api) + dev-mode no-auth on the oauth-service. (#218, #219)
- **Route delete and rename left orphans**: deleting a route now tears down its
  Ziti service + policies + `host.v1` config + service-edge-router policy, and
  prunes the APISIX route + bootstrapper target; renaming re-keys the edge wiring
  to the new host instead of stranding it under the old one. (#221)
- **BrowZer `1007` (no WSS routers) / `1016` (WSS cert)** on the clientless path,
  and the **psm Entra login loop** caused by the direct OIDC bypass. (#214, #215, #216)

### Per-app BrowZer publishing via the OpenZiti reconciler (#201–#208)

Publish multiple apps clientlessly behind BrowZer — each as its own dark Ziti
service — and toggle them from the admin console without breaking the overlay.
Motivated by publishing a second BrowZer app (`psm.tdv.org`, an external HTTPS
IIS/.NET upstream) alongside `netgraph`: the BrowZer WASM runtime sends a fixed
`Host: unknown` and **no SNI** on every overlay request, so the old shared
`browzer-router` (which demuxed apps by Host) could only ever serve one app.

#### Added
- **OpenZiti reconciler** (`internal/access/ziti_reconciler.go`, gated by
  `ZITI_RECONCILER`): declaratively converges the controller to the desired
  state read from `proxy_routes` — per-app services, bind/dial/service-edge-router
  policies, `host.v1` configs, and router/SDK hosting — on boot, a 30s tick, and
  on demand. Replaces the imperative provisioning path as the single owner of all
  Ziti mutations. (#201)
- **Per-app BrowZer services**: each clientless app gets its own Ziti service
  hosted by the edge **router** via a fixed `host.v1` config (`{protocol,address,
  port}`), so there is no Host demux — removing the single-app limit of the shared
  router. (#201)
- **`hosting_mode = 'hop'`** for Host-routed / HTTPS upstreams (e.g. IIS/.NET):
  a per-app plain-HTTP hop (nginx) that listens on a deterministic `base+index`
  port, rewrites the `Host` header, and proxies to the real upstream; emits a
  per-route landing-path 302 so the post-OIDC `/` lands on the app's entry path.
  (#202, #203)
- **Public per-app nginx vhost generator** (`internal/access/browzer_vhosts.go`,
  `BROWZER_VHOST_CONFIG_PATH`): the access-service renders one TLS `server {}` per
  `ziti+browzer`-enabled route (`server_name <app>.tdv.org` → bootstrapper
  `:8445`), so publishing a clientless app needs **no** front-nginx hand-edit.
  Hop-mode routes additionally get an external-IdP **OIDC `form_post` callback
  bypass** (`location ~ /(signin-oidc|signout-callback-oidc)$` → the route's hop
  port). Config: `BROWZER_BOOTSTRAPPER_ADDR`, `BROWZER_VHOST_SSL_CERT/KEY`,
  `BROWZER_OIDC_CALLBACK_PATHS`. A poll-reload entrypoint
  (`deployments/docker/oidx-nginx-entrypoint.sh`, wildcard-`include`d from
  `nginx.conf`) reloads the front nginx when the generated file changes. (#208)

#### Changed
- **The admin-console one-click feature toggle defers to the reconciler** when
  `ZITI_RECONCILER` is on: enable/disable only write the `proxy_routes` flags
  (`ziti_enabled` / `browzer_enabled` / `ziti_service_name`) and enqueue a
  converge — no imperative service/policy creation or SDK hosting. Imperative
  behavior is unchanged when the reconciler is off. (#206)
- `RegenerateConfigs` (the toggle path) now also rewrites the hop and public
  vhost configs, not just the bootstrapper targets and router config — so a
  newly-toggled app gets its hop/public block live without a restart. (#208)

#### Fixed
- **`psm.tdv.org` 502 + feature-manager↔reconciler conflict**: with the
  reconciler on, the UI toggle still provisioned imperatively (SDK-hosting the
  service with an `edge` terminator and `#access-proxy-clients` policies, and
  renaming `ziti_service_name`), colliding with the reconciler's router-hosted
  `tunnel` terminator — the access-proxy then forwarded plain HTTP to the app's
  `:443`. Fixed by attaching the `host.v1` config to existing services
  (`EnsureServiceConfig`, #205) and by making the toggle defer (#206).
- **BrowZer hop leaked `unknown:<port>` on server redirects**: the hop set the
  upstream `Host`, so the app emitted a correct absolute `Location`, but nginx's
  **default `proxy_redirect`** rewrote it back to the proxy's own address — and
  since the runtime's `Host` is `unknown`, that became
  `http://unknown:<port>/…` (the psm Entra-login 302). Generated hop blocks now
  emit `proxy_redirect off;`. (#207)
- **Reconciler self-heals drifted `host.v1` configs** (create-or-PATCH on data
  drift) so per-app hop-port reshuffles converge automatically with no manual
  `ziti edge delete config`. (#204)

### Dark (loopback-bound) services behind BrowZer + native client (#196)

Publish a service that is **completely dark to the outside** — bound to host
loopback, reachable only over the OpenZiti overlay — while still serving it
clientlessly via BrowZer and/or a native client.

#### Added
- **`BROWZER_HOST_LOOPBACK_ALIAS`** (env, `browzer_targets.go` `browzerUpstream()`).
  In rootless deployments the native access-proxy (a host process) reaches a dark
  target at `127.0.0.1`, but the BrowZer router (a separate network namespace,
  e.g. slirp4netns) cannot. Since both upstreams derive from one route `to_url`,
  this knob rewrites a `127.0.0.1`/`localhost` `to_url` to the alias (e.g.
  `10.0.2.2` with `allow_host_loopback`) **for the BrowZer router config only**.
  Unset (the default, e.g. docker-compose where router and app share a bridge) →
  no rewrite, behavior unchanged.
- Admin console **Identities**: a **Download `.jwt`** button on the enrollment
  modal, so a one-time enrollment token can be fed straight to
  `ziti-edge-tunnel enroll --jwt` / Ziti Desktop Edge for native (no-browser)
  access to dark services.
- `docs/OPENIDX_ZITI_ARCHITECTURE.md`: full OpenIDX + OpenZiti architecture
  guide, including a "dark services + native client" recipe (and the rootless
  loopback-alias wrinkle).

### One-click OpenZiti/BrowZer toggles on proxy routes (#195)

#### Added
- `RouteFeatureToggles` — compact **OpenZiti** and **BrowZer** switches rendered
  directly in each HTTP proxy route's action bar on the Proxy Routes page, so
  putting a route behind the overlay (and publishing it clientlessly via BrowZer)
  is a single click. BrowZer is gated on OpenZiti, matching `ServiceFeaturePanel`.
  Reuses the existing `/services/:id/features/{ziti,browzer}/{enable,disable}`
  endpoints (no backend change) and shares the `['service-status', routeId]`
  query cache with the expand panel so both stay in sync.

### Admin console bug fixes (found via Playwright page sweep)

A headless logged-in sweep of all ~83 console pages surfaced four real bugs:

#### Fixed
- **Governance endpoints returned 401 for every valid token** — governance's
  JWKS key parser ran `ProbablyPrime()` on the RSA *modulus*, which is `p×q`
  (composite by definition), so it rejected every key. All governance pages
  (access-reviews/requests, policies, abac-policies, approval-policies,
  campaigns) were unusable. Replaced with the correct odd-modulus check.
- **`GET /users/me/consents` 500** — the query selected `rt.scope` without
  including it in `GROUP BY` (SQLSTATE 42803). Now aggregates with
  `string_agg(DISTINCT rt.scope, ' ')`.
- **Migration v39** — creates `device_trust_requests`, `device_trust_settings`,
  `trusted_browsers`, `risk_policies`, which existed only in `init-db.sql` (the
  same gap class as v38), so their handlers 500'd on RDS/Helm/`migrate` deploys.
  Also made `GetDeviceTrustSettings` return defaults on no-rows instead of 500.
  *(A wider audit found ~70 more tables only in `init-db.sql`; closing that whole
  gap — and reconciling init-db.sql's own duplicate `lifecycle_executions` — is
  tracked as follow-up.)*
- **`/users` client crash** — avatar initials read `user.username[0]` without a
  null guard (`Cannot read properties of undefined`). Now uses optional chaining
  with a `'?'` fallback.
- **`/users` showed blank names/emails + "Invalid Date"** — the admin users API
  speaks SCIM (`userName`, `name.givenName`, `emails[].value`, `createdAt`,
  `active`) per the identity models + SCIM integration tests, but the console is
  flat snake_case throughout. The console now adapts SCIM↔flat for the users
  endpoint (read and create/update) in `users.tsx`, leaving the rest of the page
  flat. (Backend left unchanged — its SCIM shape is the codified contract used by
  `/scim/v2/Users` and internal oauth/webauthn callers.)
- **`/groups` showed blank descriptions, wrong type, "Invalid Date"** — same
  SCIM↔flat mismatch (`displayName`, `attributes.{description,parentId}`,
  `createdAt`). `groups.tsx` now adapts read and create/update. (Member counts
  show 0 — the list endpoint doesn't return them; an API enhancement, not a
  console fix.)
- **Other SCIM-shaped consumers** (found by auditing every console call to the
  identity user/group endpoints): the group "add member" user-search dropdown
  (`/users/search`, SCIM) and the bulk-operations group selector
  (`/groups`, a bare SCIM array — the code expected `{data:[{id,name}]}`) now
  map SCIM→flat too. Audited as already-correct: group members, user roles,
  roles, and `/users/me` (camelCase, which `user-profile` already matches).

### One-click "open internal app" — published apps as launcher tiles

#### Added
- `POST /api/v1/access/apps/:id/publish-app` publishes a registered app as a
  one-click tile: it creates a single host-level proxy route, auto-creates a
  **My Apps** launcher tile (`applications` row, `base_url` = the gated public
  URL), and registers the per-host `…/access/.auth/callback` on the
  `access-proxy` OAuth client so SSO round-trips without a manual OAuth edit.
- `ACCESS_APPS_DOMAIN` config: bare-label hosts (e.g. `netgraph`) resolve to
  `<label>.<ACCESS_APPS_DOMAIN>` so every app lives under one wildcard domain
  with a single wildcard TLS cert.
- Migration **v41**: `published_apps.public_host` + `landing_path` (where the
  tile opens, default `/`, e.g. `/ui/` for apps not served at the site root).
- Admin console **App Publish → Publish App** dialog (public host + landing
  path). Docs: `docs/app-publishing.md` "One-Click Publishing" section.

### Access-proxy forward-auth: honor X-Forwarded-Proto

#### Fixed
- The access-service built its OAuth callback (`/access/.auth/callback`) as
  `http://` from `c.Request.Host`, ignoring `X-Forwarded-Proto`. Behind a
  TLS-terminating proxy (nginx/APISIX) the public URL is HTTPS, so the emitted
  `redirect_uri` didn't match the registered/public `https://` URL and the
  browser callback hit a non-TLS port. Added a `callbackScheme()` helper
  (X-Forwarded-Proto → request TLS → http) and applied it to all four callback
  builders (the built-in access-proxy login/exchange + the external-IDP paths).

### Access-proxy / App Publish schema fix (migration v40)

#### Fixed
- **App Publish was broken on every migrate-based / RDS / Helm deploy.**
  `GET /api/v1/access/apps` 500'd because `published_apps`, `discovered_paths`
  and `service_features` lived only in `init-db.sql`; `GET /api/v1/access/routes`
  500'd with `column "idp_id" does not exist` because the `proxy_routes` (and
  `proxy_sessions`) schema had drifted ~12 columns behind `init-db.sql`
  (`idp_id`, `route_type`, `remote_host/port`, posture/risk/guacamole/browzer …).
  Migration **v40** creates the missing tables and adds the missing columns
  (idempotent). Verified by registering→discovering→publishing an internal app
  end-to-end.

### gateway-service startup fixes

`gateway-service` panicked on startup under gin v1.11.0 and never began serving
(installs fronting it with APISIX wouldn't have noticed). Three stacked bugs,
each masked by the previous panic:

#### Fixed
- **Route catch-all conflict**: each service's route file registered ~dozens of
  explicit routes *plus* a `/*path` catch-all with the identical proxy handler;
  gin v1.11.0 rejects a catch-all alongside explicit siblings (`/users`).
  Collapsed each service to the single catch-all — behaviourally identical (one
  handler, no per-route middleware) and the correct shape for a pass-through.
- **Duplicate `/health` registration**: the gateway `Service`, the standardized
  `newhealth` service, and the routes package each registered `/health` (and
  `/ready`) on the same engine → `handlers are already registered for path
  '/health'`. The gateway now uses the `Service`'s health routes only (which is
  what the k8s probes and compose healthcheck hit at `/health`).
- **Wrong proxy targets**: `serviceURLProvider` hardcoded `localhost:8501–8506`
  (ignoring env), so the gateway proxied to non-existent/incorrect ports. Fixed
  the defaults to the services' real ports (`8001/8002/8004/8005/8006`) and added
  `<SERVICE>_SERVICE_URL` env overrides (e.g. `IDENTITY_SERVICE_URL`).

### CI green-up + GetUser NULL-name fix

#### Fixed
- **`GetUser` 404'd on users with no name**: `users.first_name`/`last_name` are
  nullable, but the read scanned them into non-pointer strings, so any name-less
  user (valid per SCIM) errored the scan and surfaced as 404. The read now
  `COALESCE`s both to `''`.
- **CI Lint**: removed an ineffectual `countArgCount++` in `internal/admin/service.go`.
- **CI Integration job**: set `DEFAULT_ORG_FALLBACK=true` for the suite. It is
  single-org (most tests log in the seeded admin without an `X-Org-Slug`/subdomain
  signal); the config default flipped to `false` in v1.7.0, which had been failing
  every admin-token-dependent test. The cross-org test still sends `X-Org-Slug`
  explicitly, so isolation is still validated.

### Tenant login branding + production hardening (v1.9.0)

Per-tenant branding on both login surfaces, plus production-readiness fixes —
three of which were surfaced by a prod-like local docker-compose smoke and would
otherwise only have failed in a real multi-tenant deploy.

#### Added
- **OAuth server-rendered login page branding** (`internal/oauth/service.go`):
  `renderLoginPage` now applies the resolved tenant's `tenant_branding` (logo,
  favicon, colors, titles, custom CSS, footer, powered-by toggle) with safe
  defaults on no-org/no-row; text/attrs escaped, `custom_css` treated as trusted
  admin input. Unit test `internal/oauth/branding_test.go`.
- **SPA login branding** (`web/admin-console/src/pages/login.tsx`): applies
  favicon, secondary color, page background (color/image), injected `custom_css`,
  custom footer, and powered-by visibility — on top of the existing
  logo/primary/title/message handling.
- **Migration v38**: creates `tenant_branding`, `tenant_domains` and
  `tenant_settings` in the versioned migration set. They previously existed only
  in `deployments/docker/init-db.sql` (docker-compose), so managed-RDS/Helm
  deploys never had them — branding could not be saved and domain-based tenant
  resolution silently returned defaults. DDL is idempotent.
- **`DATABASE_SSL_MODE` plumbed through deploy configs**: parametrized in
  docker-compose (`${DATABASE_SSL_MODE:-disable}`), the Helm DB-URL secret
  (`database.sslMode`), and documented in `.env.example`. (The Go config/pool
  side already honored it.)
- **`values-prod.yaml` + runbook**: production tenancy env (`TENANT_BASE_DOMAIN`,
  `DEFAULT_ORG_FALLBACK=false`), `database.sslMode: require`, and the tenancy/RLS
  sections + multi-tenancy post-deploy smoke in `docs/DEPLOYMENT.md`.

#### Fixed
- **Public login-branding endpoint blocked in multi-tenant deploys**: the
  fail-closed `TenantResolver` rejected `GET /api/v1/identity/branding` when
  `DEFAULT_ORG_FALLBACK=false`, so the login page could never load tenant
  branding. The endpoint (which self-resolves the tenant from `?org=`/`?domain=`)
  is now exempt from tenant resolution.
- **`TestRLSBelt` was inert under a superuser DB role**: PostgreSQL superusers
  (and `BYPASSRLS` roles) ignore RLS even with FORCE, so the belt test passed
  vacuously against the default `openidx` superuser used by the postgres image
  and CI. It now runs its assertions as a dedicated `NOSUPERUSER` role —
  mirroring how production connects to RDS — making the CI gate meaningful.
  Documented the non-superuser connection requirement in `docs/DEPLOYMENT.md`.

#### Tenancy env injection (Helm)
- The `-config` ConfigMap now carries `TENANT_BASE_DOMAIN`, `DEFAULT_ORG_FALLBACK`,
  `DEFAULT_ORG_ID` and `DATABASE_SSL_MODE`, and every backend deployment mounts it
  via `envFrom` so the settings actually reach the pods.

### Multi-tenancy — RLS belt + per-org primitives (v1.8.0)

Defense-in-depth: Postgres Row-Level Security so a missing app-layer org filter
still cannot leak across tenants, plus the per-org primitives.

#### Added
- Migration **v37**: activates RLS on all 68 org-scoped tables — policies
  rewritten to `app.bypass_rls='on' OR org_id = current_setting('app.org_id')`
  with `ENABLE` + `FORCE ROW LEVEL SECURITY` (fail-closed when the GUC is unset).
- Pool-checkout GUC injection (`internal/common/database/rls.go`): each
  connection is stamped with the request's tenant scope from `orgctx`; no query
  call-site changes. `orgctx.WithBypassRLS` is the explicit opt-in for
  background/cross-org jobs (wired into ~25 ticker/sweep entrypoints + the migrator).
- Two-tenant RLS ship-gate test (`test/integration/cross_org_test.go:TestRLSBelt`):
  a raw cross-org `SELECT` returns 0 rows even with the app filter "broken".
- Per-org rate-limit buckets; `compliance_reader` org-scoped read-only audit role;
  admin-console **Branding** page; `docs/multitenancy-upgrade-runbook.md`.

#### Changed
- **BREAKING (operational):** with RLS forced, direct SQL against org-scoped
  tables sees no rows unless the session sets `app.org_id` (or
  `app.bypass_rls='on'`). See the upgrade runbook.

### Multi-tenancy — App-layer enforcement (v1.7.0)

The v2.0 multi-tenancy epic's enforcement milestone. Every service query now
reads `org_id` from request context and filters/populates by it
(`orgscope ./internal` = 0), and tenant isolation is **activated**.

#### Added
- Cross-org integration test (`test/integration/cross_org_test.go`): a token
  scoped to org A gets **404** (not 403) reading org B's data; a platform admin
  (`super_admin`) may read cross-org via `X-Org-ID` and every such access writes
  an `audit_events` row (`platform_admin_cross_org_access`).
- Platform-admin bypass + mandatory audit, wired through the `TenantResolver`
  (`OnPlatformCrossOrg` hook + `auth.SuperAdminPredicate`).
- Per-tenant JWT `iss` and per-tenant OIDC discovery, derived from the org slug
  and `TENANT_BASE_DOMAIN`.
- Admin-console tenant selector (super_admin-only) that scopes requests via
  `X-Org-Slug`.
- `orgscope` is now a hard CI gate (`-fail`).

#### Changed
- **BREAKING (config):** `DEFAULT_ORG_FALLBACK` now defaults to **false** — a
  request that resolves no tenant is rejected (400) instead of being scoped to
  the default org. Single-tenant installs must set `DEFAULT_ORG_FALLBACK=true`.
- JWT `iss` is per-tenant when `TENANT_BASE_DOMAIN` is set (token-format change;
  global issuer otherwise, so single-tenant installs are unaffected).

## [1.6.0] - 2026-06-11

**Multi-tenancy Foundation milestone.** First of four releases in
the v2.0 multi-tenant SaaS isolation epic (`docs/v2-multitenancy-
design.md`). v1.6.0 lays the schema + plumbing groundwork **without
changing any behavior** for existing single-tenant installs — the
ship gate for this milestone is "existing functionality unchanged."

Multi-tenancy enforcement comes in v1.7.0 (service-layer query
scoping) and v1.8.0 (RLS belt + per-org primitives). v1.6.0 is the
foundation other releases build on.

### Added

- **`internal/common/orgctx` package** (#136). Pure-additive
  `context.Context` carrier for the resolved organization (UUID id
  + slug) and a platform-admin marker. The tenant-resolution
  middleware writes into it; v1.7.0 service code reads from it.
  `With` / `From` / `MustFrom` / `WithPlatformAdmin` /
  `IsPlatformAdmin` exposed with `ErrNoOrgContext` sentinel. 10
  unit tests.

- **`internal/common/middleware.TenantResolver`** (#140). The gin
  middleware that resolves the request's organization from
  `X-Org-Slug` header (gateway-set from subdomain), JWT `org_id`
  claim already attached by the Auth middleware, or `X-Org-ID`
  header (platform-admin only). Falls back to the install's
  default org so single-tenant installs keep working unchanged.
  Defines the `OrgLookup` interface and `ErrOrgNotFound`
  sentinel. 16 unit tests covering every resolution path.

- **`tools/orgscope` CLI** (#141). Static helper that walks
  `internal/` looking for SQL statements targeting a scoped
  table without an `org_id` reference. Filters out gin's
  `c.Query("client_id")`-style false positives by checking that
  the string literal starts with a SQL keyword. Mirrors v36's
  scoped-table list (68 tables, with documented install-wide
  exclusions). Wired into Go CI as an **informational job**
  ("Org-scope lint") that posts findings to the run summary but
  never gates a PR — v1.7.0 will promote to `-fail` once the
  service-layer refactors complete. Baseline on current `main`:
  ~1096 findings, each a concrete v1.7.0 refactor target. 28
  unit + fixture tests.

- **`docs/v2-multitenancy-design.md`** (#135). The architectural
  design doc the v1.0 plan called out as a v2 prerequisite.
  Captures three approved decisions (tenant resolution model,
  app-layer + Postgres RLS defense-in-depth, automatic `'default'`
  org backfill for existing installs), the four-milestone delivery
  plan (v1.6 → v2.0), out-of-scope items, risk register, sizing.

### Changed (schema)

- **Migration v34** (#137) — `org_id UUID NULL` column +
  `idx_<table>_org_id` index added to ~55 tables that migration
  v25 didn't reach (api_keys, mfa_*, oauth_*_tokens, ziti_*,
  scim_*, directory_*, privacy_*, posture_*, governance tables,
  …). Idempotent via `IF NOT EXISTS`. Six tables explicitly **not**
  scoped because they are install-wide rather than tenant-data:
  `organizations`, `permissions`, `system_settings`,
  `ip_threat_list`, `posture_check_types`, `policy_sync_state`.

- **Migration v35** (#138) — Backfills the default organization
  UUID (`00000000-0000-0000-0000-000000000010`, created by v25)
  into every NULL `org_id` row across v34's scoped set. Idempotent
  via `WHERE org_id IS NULL` guards. Down is narrower: only
  reverses rows currently holding the default UUID, so multi-org
  installs (none today) stay intact.

- **Migration v36** (#139) — Final foundation migration. For each
  of the 68 scoped tables, applies `SET DEFAULT '<default-org-
  uuid>'` (preserves ship gate — INSERTs that omit `org_id`
  silently land in default), `SET NOT NULL`, `ADD CONSTRAINT
  fk_<t>_org … REFERENCES organizations(id) ON DELETE RESTRICT`,
  and `CREATE POLICY pol_<t>_org_scope … PERMISSIVE … USING
  (true)`. **RLS is NOT enabled** on the tables — v1.8.0 owns
  activation by `ALTER POLICY` to a real org filter + `ALTER TABLE
  … ENABLE ROW LEVEL SECURITY`. v1.7.0's final PR will `DROP
  DEFAULT` once every INSERT path is org-context-aware.

### Notes for operators

- **No operator action required.** Migrations are
  forward-only-idempotent and `default` org is created
  automatically. The install behaves as a single-tenant install
  did before, just with the multi-tenancy plumbing ready
  underneath.
- **Migration v36 caveat:** `SET NOT NULL` on a table with very
  many rows (audit_events, login_history at scale) runs a
  validation scan. v35 backfilled every existing row so the scan
  succeeds, but for the largest installs we recommend the
  migration runs during a maintenance window.
- `tools/orgscope` baseline (~1096 unscoped queries) is **not**
  a regression — it documents the surface v1.7.0 will refactor.
  The CI job posts the count informationally; PRs are not gated.

### What's NOT in this release

- No enforcement of org scoping. Service code still ignores
  `orgctx`. Queries do not filter by `org_id` yet. RLS is not
  enabled. (v1.7.0 owns the app-layer enforcement; v1.8.0 owns
  RLS.)
- No tenant signup UI, billing, hard quotas, per-tenant signing
  keys, schema/db-per-tenant — those are explicitly out of scope
  for the entire v2.0 epic; see the design doc.

## [1.5.0] - 2026-06-11

A docs-only release that closes the last open P2 backlog item from
the v1.0 plan. No code change; safe to skip if you're already on
v1.4.0 and don't need the new operator-facing docs.

### Added
- **`docs/SECURITY-HARDENING.md`** (#133). Production-readiness
  checklist where every "hard requirement" row maps to a check in
  `Config.ValidateProduction()` — the in-process blocking startup
  gate that already refuses to bring up a misconfigured production
  deploy. Covers the secrets / transport / CSRF-CORS-audit-stream /
  debug-knob sections the validator gates on, plus an "outside the
  validator" section for the operational items that aren't config
  flags. The policy at the bottom nails down validator-first,
  doc-update-in-the-same-PR.
- **`docs/SECURITY-TENANCY.md`** (#133). Explicit, prose statement
  of the single-tenant assumption the v1.0 plan made and the v1.x
  releases preserved. Describes what is shared (data layer,
  identity, authorization, audit), what we do support (federation
  across IdPs, per-app authz, per-customer deployments), and what
  we don't (row-level tenant isolation, per-tenant signing keys,
  per-tenant rate limits, per-tenant audit isolation) — and why
  each is intentional, not a gap.

### Changed
- **`SECURITY.md`** Deployment section trimmed (#133). The previous
  generic OWASP-ish bullet list duplicated marketing copy from the
  README and overlapped with the new hardening doc by 90%. Replaced
  with two pointers to `SECURITY-HARDENING.md` and
  `SECURITY-TENANCY.md` plus the lock-step policy. Vuln reporting
  and supported-versions sections are unchanged.
- **`README.md`** Overview (#133). Adds a prominent blockquote that
  states the single-tenant assumption in one sentence and links to
  `docs/SECURITY-TENANCY.md`. First-impression accuracy for readers
  who would otherwise spend time evaluating us against a multi-
  tenant SaaS use case we don't support.
- **`docs/GETTING-STARTED.md`** "Initialize Database" step (#133).
  The old step told operators to run `\i migrations/001_create_tables.sql`
  — a pre-historic flow. Replaced with the supported path: build
  `cmd/migrate`, run `migrate up`, verify with `migrate status`.
  Plus a top-of-doc callout pointing readers at the new hardening
  and tenancy docs before any production deploy.

### Notes
- v1.4.0 deployments upgrade in place. The release tags the v1.5.0
  binaries identically to v1.4.0; if you don't pull the docs, the
  upgrade is a no-op.

## [1.4.0] - 2026-06-11

A short, focused security-hardening release. Three independent P1/P2
items the v1.0 plan called out, each landed as its own commit with
defense-in-depth tests:

### Changed
- **Dynamic UPDATE builders now run behind a column allow-list**
  (#129). Both `updateSAMLServiceProvider`
  (`internal/oauth/saml_sp.go`) and the
  `/access/paths/:pathID/classification` handler
  (`internal/access/app_publish.go`) used to build their SQL with
  `fmt.Sprintf("col = $%d", argIdx)` scattered through one if-block
  per column. The literals were hardcoded so the pattern was not
  actively exploitable, but the blast radius was wide: one refactor
  wiring a request-derived string into a Sprintf would have introduced
  a real SQL-injection vector. The new `buildUpdateClause` helper
  takes a per-caller column allow-list, validates each candidate
  against both that map and a strict identifier regex
  (`^[a-z_][a-z0-9_]{0,62}$`), and refuses to build the query when
  anything else slips through. Unit tests pin the rejection paths.
- **Migration lock acquisition retries up to 30 s before giving up**
  (#130). Previously `acquireLock` returned instantly on conflict —
  fine for a single admin-driven `cmd/migrate up`, but it raced in
  containerized environments where the migrate job and the
  identity-service / oauth-service replicas were all coming up against
  the same database at startup. Whichever migrator won the race ran
  the migrations; every other process exited with "lock is already
  held" and the orchestrator restarted them in a crash loop. The lock
  now retries every 500 ms for up to 30 s before reporting failure.
  Stale-lock recovery (15 min) is unchanged. A real DB error (not
  `errLockBusy`) still surfaces on the first try — only conflicts
  retry. Six unit tests pin the new behavior including
  context-cancellation handling.
- **CSRF protection is on by default** (#131). The
  `csrf_enabled` default flipped from `false` to `true`. The
  production gate (`ValidateProduction`) caught the old default
  anyway, but every non-prod environment had to remember to opt in.
  Operators now opt out (`CSRF_ENABLED=false`) only when they know
  they need to.

### Fixed
- **`internal/access/ziti.go` was hardcoding
  `tls.Config{InsecureSkipVerify: true}` unconditionally** (#131).
  The line ran before the CA-loading branch, which then bolted a
  `RootCAs` pool onto the TLS config — but `InsecureSkipVerify=true`
  nullifies every CA after it, so the verification path was doing
  nothing for security and the connection was insecure regardless of
  the operator's intent. Replaced with:
  - Load `ZitiIdentityDir/ca.pem` → use it for proper validation
    (the desired path).
  - Missing CA + `ZitiInsecureSkipVerify=true` → log a warning and
    use `InsecureSkipVerify` (the dev-loop escape hatch).
  - Missing CA + `ZitiInsecureSkipVerify=false` → refuse to start
    with a hint pointing at both knobs (the production refusal).

### Security
- **`ValidateProduction()` now rejects two new misconfigurations**
  (#131):
  - `redis_tls_skip_verify=true`
  - `ziti_insecure_skip_verify=true`
  Both are dev-loop escape hatches against self-signed certs in a
  local docker stack; in production they silently erase the trust
  chain on the link they cover. The blocking startup gate
  (`security_check.ValidateProductionConfig`) now ensures production
  deploys can't ship with either flag on.

### Notes
- All v1.3.0 deployments upgrade in place. The CSRF default flip and
  the new skip-verify production gates are the only behavioral
  changes most operators will see; the SQL builder and migration lock
  refactors are internal.

## [1.3.0] - 2026-06-11

A focused follow-on release driven by the P1.5 backend-test sweep —
which surfaced (and made us fix) two real OAuth-flow bugs and one
missing schema migration that production deployments had been
silently broken on since the QR-login feature shipped.

### Added
- **Backend unit-test coverage on previously untested seams** (#122):
  - `internal/oauth/authorize_handler_test.go` — the methods on
    `*AuthorizeHandler` (`validateRedirectURI`, `validateResponseType`,
    `validateScope`, `validatePKCEParameters`, `parseAuthorizeRequest`)
    were 0% covered; new file takes them to 100% without bringing up
    a Service / Redis / DB.
  - `internal/common/netutil/ssrf_test.go` — entire package was
    untested. `DefaultSSRFConfig`, `ValidateURL` (scheme / localhost /
    private-IP / no-hostname / allowlist-miss branches),
    `domainMatches`, `isPrivateIP` (RFC 1918 + RFC 4193 boundaries),
    `isLocalhostIP`, `IsPrivateURL`, `KnownPublicAPIs` sanity. Uses
    literal IPs so the test stays off DNS. **Package coverage
    0 % → 66.2 %**.
  - `internal/common/events/bus_test.go` — entire package was
    untested. `Event` constructor + fluent setters + `JSON`,
    `MemoryBus` subscribe / wildcard / all / with-filter / unsubscribe /
    publish-returns-last-error / close-rejects-publish /
    `PublishAsync`-delivers, and the package-level global-bus wrappers.
    **Package coverage 0 % → 100 %**.
- **Integration coverage for stepup + passwordless** (#123, #126,
  #127). Two new test files (`test/integration/stepup_test.go`,
  `test/integration/passwordless_test.go`) exercise 13 routes /
  ~25 cases. The stepup happy-path round-trip and the QR-login
  create / poll happy paths are now part of the gating integration
  suite.
- **Database migration v33: `qr_login_sessions`** (#127). The table
  `internal/identity/passwordless.go` has been `INSERT`-ing into since
  the QR-login feature shipped — but which no migration ever created.
  Every `POST /oauth/qr-login/create` therefore 500'd at the first
  `INSERT` against "relation does not exist". Surfaced by PR #126's
  integration tests; was previously masked by the broken-session-id
  validator (see Fixed below). Schema mirrors the column set the
  package already reads/writes (id, unique session_token, qr_code_data,
  status enum, nullable user_id, JSONB device blobs, IP, four
  lifecycle timestamps) plus indexes on `(status, created_at)` and a
  partial `user_id` index for the post-scan lookups.

### Fixed
- **`/oauth/stepup-*` returned 401 for every valid bearer token**
  (#126, closes #124). The three step-up routes were registered
  against the bare `/oauth` group with no auth middleware in front of
  them. The handlers read `user_id` and `session_id` from the gin
  context — but nothing populated them, because no middleware ran the
  JWT parse. The fix wraps the routes with `authMiddleware` the same
  way the `/oauth/authorize` consent endpoint already does. As a
  defense-in-depth follow-on, `handleAuthorizationCodeGrant` also now
  falls back to a DB lookup for the user's most-recent active session
  when the Redis `authcode_session:<code>` bridge is empty, so the
  access token always carries a usable `sid` claim.
- **`isValidSessionID` rejected every real `login_session`** (#126,
  closes #125). The validator required a strict 36-character UUID,
  but `/oauth/authorize` produces `login_session` via
  `GenerateRandomToken(32)` — a 44-character padded base64url token.
  The mismatch broke QR login, MFA OTP, passkey, and magic-link-verify
  end to end against the actual auth flow. `isValidSessionID` now
  accepts either form: a 36-character UUID, OR a 32..128-character
  base64url token with optional `=` padding. Both still exclude `:`,
  `/`, whitespace, and control bytes — Redis-key injection / path
  traversal stays blocked. Unit tests expanded to 23 cases covering
  the UUID happy path, the base64url happy path with and without
  padding, length boundaries, and the full injection-shaped rejection
  set.

### Notes
- All v1.2.0 deployments upgrade in place. Migration v33 applies on
  startup through the standard migration runner; the table is empty
  on first use and the OAuth service starts populating it
  immediately.

## [1.2.0] - 2026-06-10

A follow-on minor release closing the rest of the P1 and P2 backlog items
queued behind v1.1.0, plus a full sweep through the admin-console test
suite. Every admin-console page is now covered.

### Added
- **GDPR DSAR processor.** `Service.ExecuteDSAR` now actually fulfills
  data-subject access requests instead of marking them "received":
  - `export` (Article 15) compiles 12 categories of subject data (profile,
    consents, sessions, audit events, roles, groups, app assignments,
    access requests, MFA TOTP, MFA WebAuthn, MFA push, prior DSARs).
  - `delete` (Article 17) erases the subject's records.
  - `restrict` (Article 18) flags the subject for restricted processing.
  A background processor (`StartDSARProcessor`) auto-executes new `export`
  requests; `delete` and `restrict` stay manual on purpose. Backed by
  schema migration v32 (privacy tables) (#118).
- **Outbound resilience.** New `internal/common/resilience` package wraps
  external OAuth / SAML / OIDC discovery calls behind a circuit breaker
  (`ResilientHTTPClient` + per-host `Registry`). Long IdP outages no
  longer drag the whole login path down (#117).
- **Frontend test coverage: 100%.** Every page under
  `web/admin-console/src/pages/` (87 in total) now has a vitest suite.
  Suite is 114 files / 684 tests. Patterns established for fixtures with
  TanStack Query, Radix listeners, fetch-direct pages, route params, and
  `useAuth` mocks (#120).

### Changed
- **Application access requests are fulfilled end-to-end.** Approving an
  access request whose `resource_type == application` now provisions the
  application binding through `internal/provisioning`. Prior to this it
  marked the request approved and warned (#117).
- **Certification reviews now enforce decisions.** Reviewing an item
  with `decision == revoke` (whether per-item or via the campaign's
  `revokeUnreviewedItems`) actually revokes the underlying role / group /
  app assignment instead of just recording the decision (#117).

### Fixed
- **Session-cleanup race-detector flake.** `TestSessionService_Session-`
  `ExpirationCleanup` no longer relies on `miniredis.FastForward`, which
  raced the cleanup goroutine when `-race` was on. The test uses a real
  1 s TTL plus a 1.1 s sleep; the helper also closes its Redis client
  via `t.Cleanup` so leaked goroutines don't carry across tests (#119).

### Notes
- v1.1.0 deployments upgrade in place. The new privacy tables (migration
  v32) apply on startup through the standard migration runner.

## [1.1.0] - 2026-06-09

The first minor release after v1.0.0 — three weeks of post-release hardening
focused on real security gaps that integration tests surfaced, plus the
infrastructure to keep them from coming back.

### Added
- **`POST /api/v1/identity/users/:id/set-password`** — direct admin
  password-set endpoint. Hashes via `Service.SetPassword` so password-history
  and policy enforcement apply. Closes the "admin onboards a non-SSO user"
  gap that previously had no API path (#112).
- **`GET /api/v1/identity/users/me/sessions`** — the self-access counterpart
  of the existing admin-only `/users/:id/sessions`. Sources user id from the
  JWT (#114).
- **`GET /api/v1/identity/users/me/mfa/status`** — self-service MFA status
  endpoint. Returns the user's enabled primary factors as an array, distinct
  from the admin-console toggle map at `/mfa/methods`. Backup recovery codes
  are intentionally excluded — they're not a primary factor on their own
  (#114).
- **Integration test suite is now mandatory in CI**. The full 24-test suite
  (Postgres + Redis ephemeral services, real identity + oauth-service
  binaries) runs on every PR; any regression in identity / OAuth / MFA /
  WebAuthn / session flows blocks the merge (#115).

### Changed
- **Token revocation is now enforced at `/oauth/userinfo`.** PR #82 made
  `internal/auth.ValidateToken` fail-closed on revocation, but the OAuth
  service had its own JWT-parse path that never consulted the revocation
  store — `/oauth/revoke`, `/oauth/logout`, and `/oauth/logout-all` were
  redirect-theater. Now backed by two Redis-keyed mechanisms:
  - Per-token blacklist keyed by `sha256(token)`, TTL = remaining token
    lifetime. Used by `/oauth/revoke` and single-session `/oauth/logout`
    (when called with a Bearer).
  - Per-user revocation cutoff (`oauth:user_tokens_revoked_at:<userID>`).
    Used by `/oauth/logout-all` and by OIDC RP-initiated `/oauth/logout`
    when no Bearer is supplied — every token whose `iat ≤ cutoff` is
    rejected by `/oauth/userinfo` (#112, #114).
- **Refresh-token rotation now happens on every `grant_type=refresh_token`
  exchange** (RFC 6749 §6 / RFC 6819 §5.2.2.3). A new random refresh token
  is issued, the old one is deleted *after* the new one's INSERT succeeds,
  and the response carries the rotated token. Clients that don't store the
  rotated token will get `invalid_grant` on the next refresh — this is the
  intended security improvement (#114).
- **`Service.CreateUser` now mirrors the generated UUID back to the
  caller's struct**, so `c.JSON(201, user)` returns a usable `id` and the
  downstream "user.created" webhook + email-verification token insert see a
  real value instead of an empty string (#112).
- **SCIM `active` field now properly maps to the database `enabled` column**
  in `FromUser`. Previously, SCIM-conformant clients posting
  `{"active": true}` silently created users with `enabled=false`, and every
  admin handler queried `WHERE enabled = true` (#112).
- `handleAdminSetPassword` validates `:id` as a UUID up-front (#112).
- `handleRevoke` now signature-verifies the access token before blacklisting
  it (closes a CodeQL "missing JWT signature check" finding) (#112).

### Database
- **Migration v30**: `ALTER TABLE user_roles ADD COLUMN expires_at TIMESTAMPTZ`.
  The column was already referenced by `GenerateJWT` and the role-expiry
  cleaner, but never existed in the v1 schema — every JWT issuance returned
  an empty `roles` claim, which then 403'd the post-#79 admin-API authz gate
  (#105).
- **Migration v31**: `ALTER TABLE oauth_refresh_tokens ADD COLUMN session_id
  UUID`. The column was added when session-bound rotation landed but never
  made it into the schema migrations. Postgres rejected every INSERT, the
  error was swallowed in `handleAuthorizationCodeGrant`, and clients got
  refresh tokens that were never persisted — every `grant_type=refresh_token`
  then 400'd with `invalid_grant` (#114).

### Fixed
- `audit-service` registers the Redis health check it had been silently
  missing — every other service in the fleet was already checking Redis (#109).
- SAML SP metadata: corrected SA5008 XML tag conflicts on
  `Organization{Name,DisplayName,URL}` (#99).
- `internal/oauth/service.go` and `internal/identity/service.go` cleared
  CodeQL "log entries from user input" findings introduced by the new admin
  endpoints (#112).
- Ratelimit test window flake (#98).
- Frontend type-check and test command scripts (#88, #89).
- Race-condition CI job added (#91).
- CVE bumps: Go toolchain 1.25.11, `go-jose/v4` 4.1.4 (#104, #97).

### Test coverage
- `internal/migrations` unit tests for `allMigrations()` integrity (versions
  contiguous, no gaps, no empty SQL) and `splitSQL` behavior pins (#111).
- `internal/oauth.generateStepUpToken` sign/verify round-trip + claim
  shape (#111).
- `internal/oauth.isValidSessionID` regex-gate locked down across 15 cases
  including path traversal, separator injection, newline injection (#111).
- Frontend smoke coverage on top admin pages (#101).

### Docs
- `docs/PRODUCTION-READINESS.md` — end-to-end "can I deploy this?"
  assessment, 35-item pre-deployment checklist, full feature inventory,
  known-gaps register, deployment paths for Docker Compose / Helm /
  Terraform-EKS (#113).

### Upgrade notes
- **OAuth clients** with refresh tokens: after upgrade, the first
  `grant_type=refresh_token` exchange rotates the token. Persist the new
  `refresh_token` from the response; the old one is invalidated. Clients
  that ignore the rotated token will fail at the *second* refresh, not the
  first — make sure your client code stores the new value.
- **Browser SPAs** relying on the legacy "access token survives logout"
  bug: after upgrade, RP-initiated logout actually kills the access token.
  This is the desired behavior; UI flows that depended on the old leak
  should be reviewed.
- **Database**: two new migrations (v30, v31). Both are
  `ALTER TABLE ADD COLUMN IF NOT EXISTS` with nullable columns — backward
  compatible, fast on production-sized tables, no downtime required.

## [1.0.0] - 2026-05-22

The first tagged release: a hardened, single-tenant, self-hostable v1.

### Added
- Production deployment runbook (`docs/DEPLOYMENT.md`) anchored to the
  `ValidateProduction()` startup gate.
- Observability stack wired into the canonical compose file (Prometheus,
  Alertmanager, Grafana with provisioned dashboards, Loki/Promtail, Jaeger).
- GHCR image pipeline: multi-arch (amd64/arm64) images published to
  `ghcr.io/mhmtgngr/openidx/<service>` on every `main` push and `vX.Y.Z` tag,
  now version-stamped (the tag or commit SHA) and surfaced at `/health`.
- Helm `values-prod.yaml` (pinned tags, autoscaling, NetworkPolicies, external
  secrets, managed datastores) and a Helm chart CI workflow.
- Terraform remote-state backend bootstrap (`deployments/terraform/bootstrap/`)
  and a Terraform fmt/validate CI workflow.
- Compile gate for the build-tagged integration test suite, plus an ephemeral
  Postgres/Redis integration-test CI job.
- Backup/restore: real S3 upload and restore-from-S3 wired through the
  `Storage` interface (the previously-unused `S3Storage` backend), with a
  corrected disaster-recovery runbook.

### Changed
- Project status / feature docs rewritten to reflect the real (much more
  complete) state of the codebase.
- Adopted golangci-lint v2 and cleared the lint backlog: enforced `gofmt`,
  `govet`, `ineffassign`, `unconvert`, `bodyclose`, `staticcheck` (SA bug-class)
  and `unused`; removed dead code. `errcheck` remains intentionally deferred
  (dominated by intentional fire-and-forget calls and optional request-body
  binds).

### Fixed
- Frontend `eslint` configuration repaired; 18 stale frontend tests fixed
  (full suite green).
- Security Scanning workflow no longer reports false-red (image-scan gating;
  Semgrep SARIF upload made non-blocking).
- Backup storage: removed misleading "not initialized" panic placeholders and
  added the package's first tests.
- Schema migrations recover a stale advisory lock (from a crashed holder)
  instead of deadlocking on startup.

### Security
- **Identity admin API now enforces authorization.** The `/api/v1/identity`
  routes are deny-by-default: self-service paths (`/users/me`, MFA enrollment,
  trusted browsers, risk assessment, resend-verification) remain available to
  the authenticated user, but every other identity route now requires the
  `admin`/`super_admin` role. Previously these routes were authenticated but
  not authorized.
- **Token revocation is now enforced.** `RevokeUserTokens` previously wrote a
  per-user revocation marker that was never consulted; tokens issued before a
  revocation are now rejected. Added opt-in fail-closed validation
  (`WithRevocationRequired`) for production.
- **Auth endpoints fail closed under load-shedding.** The distributed rate
  limiter now rejects auth-sensitive requests (login, token, OTP, magic-link,
  password-reset, step-up) when its Redis backend is unavailable, instead of
  silently failing open, and covers more sensitive paths.

### Known limitations (v1)
- **Single-tenant.** One organization per deployment; multi-tenant SaaS
  isolation is not implemented.
- OAuth token introspection does not yet reflect revocation; access-token
  revocation propagates within the access-token TTL (15 min).
- Several built-but-unwired features remain (flagged `TODO(unwired)` in code):
  session idle/absolute-timeout enforcement, SAML SLO session tracking,
  reverse-proxy hop-by-hop header stripping, and audit-stream SIEM config
  endpoints.


[Unreleased]: https://github.com/mhmtgngr/openidx/compare/v1.34.0...HEAD
[1.34.0]: https://github.com/mhmtgngr/openidx/compare/v1.33.3...v1.34.0
[1.33.3]: https://github.com/mhmtgngr/openidx/compare/v1.33.2...v1.33.3
[1.33.2]: https://github.com/mhmtgngr/openidx/compare/v1.33.1...v1.33.2
[1.33.1]: https://github.com/mhmtgngr/openidx/compare/v1.33.0...v1.33.1
[1.33.0]: https://github.com/mhmtgngr/openidx/compare/v1.32.0...v1.33.0
[1.32.0]: https://github.com/mhmtgngr/openidx/compare/v1.31.0...v1.32.0
[1.31.0]: https://github.com/mhmtgngr/openidx/compare/v1.29.0...v1.31.0
[1.29.0]: https://github.com/mhmtgngr/openidx/compare/v1.28.0...v1.29.0
[1.28.0]: https://github.com/mhmtgngr/openidx/compare/v1.27.0...v1.28.0
[1.27.0]: https://github.com/mhmtgngr/openidx/compare/v1.26.0...v1.27.0
[1.26.0]: https://github.com/mhmtgngr/openidx/compare/v1.25.0...v1.26.0
[1.25.0]: https://github.com/mhmtgngr/openidx/compare/v1.24.11...v1.25.0
[1.24.11]: https://github.com/mhmtgngr/openidx/compare/v1.24.9...v1.24.11
[1.24.9]: https://github.com/mhmtgngr/openidx/compare/v1.24.8...v1.24.9
[1.24.8]: https://github.com/mhmtgngr/openidx/compare/v1.24.7...v1.24.8
[1.24.7]: https://github.com/mhmtgngr/openidx/compare/v1.24.6...v1.24.7
[1.24.6]: https://github.com/mhmtgngr/openidx/compare/v1.24.5...v1.24.6
[1.24.5]: https://github.com/mhmtgngr/openidx/compare/v1.24.4...v1.24.5
[1.24.4]: https://github.com/mhmtgngr/openidx/compare/v1.24.3...v1.24.4
[1.24.3]: https://github.com/mhmtgngr/openidx/compare/v1.24.2...v1.24.3
[1.24.2]: https://github.com/mhmtgngr/openidx/compare/v1.24.1...v1.24.2
[1.24.1]: https://github.com/mhmtgngr/openidx/compare/v1.24.0...v1.24.1
[1.24.0]: https://github.com/mhmtgngr/openidx/compare/v1.23.5...v1.24.0
[1.23.5]: https://github.com/mhmtgngr/openidx/compare/v1.23.4...v1.23.5
[1.23.4]: https://github.com/mhmtgngr/openidx/compare/v1.23.3...v1.23.4
[1.23.3]: https://github.com/mhmtgngr/openidx/compare/v1.23.2...v1.23.3
[1.23.2]: https://github.com/mhmtgngr/openidx/compare/v1.23.1...v1.23.2
[1.23.1]: https://github.com/mhmtgngr/openidx/compare/v1.23.0...v1.23.1
[1.23.0]: https://github.com/mhmtgngr/openidx/compare/v1.22.0...v1.23.0
[1.22.0]: https://github.com/mhmtgngr/openidx/compare/v1.21.1...v1.22.0
[1.21.1]: https://github.com/mhmtgngr/openidx/compare/v1.21.0...v1.21.1
[1.21.0]: https://github.com/mhmtgngr/openidx/compare/v1.20.0...v1.21.0
[1.20.0]: https://github.com/mhmtgngr/openidx/compare/v1.19.0...v1.20.0
[1.19.0]: https://github.com/mhmtgngr/openidx/compare/v1.18.0...v1.19.0
[1.18.0]: https://github.com/mhmtgngr/openidx/compare/v1.17.0...v1.18.0
[1.17.0]: https://github.com/mhmtgngr/openidx/compare/v1.16.1...v1.17.0
[1.16.1]: https://github.com/mhmtgngr/openidx/compare/v1.16.0...v1.16.1
[1.16.0]: https://github.com/mhmtgngr/openidx/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/mhmtgngr/openidx/compare/v1.14.1...v1.15.0
[1.14.1]: https://github.com/mhmtgngr/openidx/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/mhmtgngr/openidx/compare/v1.13.1...v1.14.0
[1.13.1]: https://github.com/mhmtgngr/openidx/compare/v1.13.0...v1.13.1
[1.13.0]: https://github.com/mhmtgngr/openidx/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/mhmtgngr/openidx/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/mhmtgngr/openidx/compare/v1.10.1...v1.11.0
[1.10.1]: https://github.com/mhmtgngr/openidx/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/mhmtgngr/openidx/compare/v1.9.1...v1.10.0
[1.9.1]: https://github.com/mhmtgngr/openidx/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/mhmtgngr/openidx/compare/v1.8.2...v1.9.0
[1.8.2]: https://github.com/mhmtgngr/openidx/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/mhmtgngr/openidx/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/mhmtgngr/openidx/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/mhmtgngr/openidx/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/mhmtgngr/openidx/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/mhmtgngr/openidx/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/mhmtgngr/openidx/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/mhmtgngr/openidx/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/mhmtgngr/openidx/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/mhmtgngr/openidx/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/mhmtgngr/openidx/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mhmtgngr/openidx/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mhmtgngr/openidx/releases/tag/v1.0.0

<!-- [1.24.10] has a section above but no v1.24.10 tag was ever pushed, so it has
     no compare link. Left as-is rather than invented. -->
