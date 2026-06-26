# Governance policy engine (governance slice G1) — design

## Context

"Wire up governance." Exploration showed the policy engine is **already built but starved**: the five per-type evaluators (`separation_of_duty`, `risk_based`, `timebound`, `location`, `conditional_access`) are fully implemented (`internal/governance/service.go:776–1038`) and operate on `policy.Rules[].Condition`. The access-proxy already calls `POST /policies/:id/evaluate` (`internal/access/service.go:2483` `evaluatePolicies`) for every route with `policy_ids`, sending a rich context (`user_id, roles, ip, time, path, method, route, risk_score, device_trusted, auth_methods, location, …`) and honoring `{allowed, step_up_required}`.

**The one blocking bug:** `GetPolicy` (`service.go:588`) selects only the `policies` row and **never loads `policy_rules`**, so `policy.Rules` is always empty. `EvaluatePolicy → GetPolicy → <evaluator>` then loops over zero rules and returns `true` (allow). `handleEvaluatePolicy`'s step-up loop has the same problem. `ListPolicies` (`service.go:609`) already loads rules correctly — so the rule-loading query is proven.

Settled (no work): the `inline_policy` DSL (`internal/access/policy_dsl.go`) is a separate, already-working mechanism and **cannot be reused** here (it lives in `internal/access`, which imports `internal/governance` → reusing it would be a circular import). G1 keeps the existing per-type evaluators.

## Design

### 1. Fix rule loading (the core change)
Extract a shared `loadPolicyRules(ctx, policyID, orgID) ([]PolicyRule, error)` helper, used by both `GetPolicy` and `ListPolicies`, and have `GetPolicy` set `policy.Rules` from it. `GetPolicy` previously never loaded rules at all.

**Root cause found during live verification (corrects the spec's original assumption):** `ListPolicies`' rule query was *not* working — it `SELECT id, condition, effect, priority FROM policy_rules`, but the real table has **`id, policy_id, rule_type, conditions, actions, created_at, org_id`** (no `condition`/`effect`/`priority` columns). The query errored every call (`column "condition" does not exist`), and `ListPolicies` swallowed it (`Warn` + `continue`), so rules came back empty there too. The in-memory evaluator tests never caught this because they bypass the DB. So the engine was starved on *both* paths, not just `GetPolicy`.

The write side (`CreatePolicy`/`UpdatePolicy`) stores `rule.Effect` in `rule_type`, `rule.Condition` in the `conditions` JSONB, and `{effect, priority}` in the `actions` JSONB. `loadPolicyRules` reads them back from exactly there (`rule_type`/`actions.effect` → `Effect`, `conditions` → `Condition`, `actions.priority` → `Priority`), ordered by `(actions->>'priority')::int DESC NULLS LAST, created_at`. This single corrected helper activates all five evaluators **and** the step-up loop on both `GetPolicy` and `ListPolicies`.

### 2. Verify the evaluators (unit tests)
The evaluators have never run against loaded rules. Add a focused test per type that builds a `Policy` with `Rules` + an evaluation `request` map and asserts the decision:
- `timebound`: deny outside `start_hour..end_hour` / disallowed weekday; allow inside.
- `separation_of_duty`: deny when the user holds ALL `conflicting_roles`; allow otherwise.
- `location`: deny when the IP matches no `allowed_ip_prefixes`.
- `risk_based`: deny when accumulated risk ≥ `risk_threshold`.
- `conditional_access`: deny + `step_up_required` when `require_mfa`/`device_trust_required`/`max_risk_score` fail.
These call the evaluators directly (in-memory `Rules`), so they don't need a DB and pin the logic the `GetPolicy` fix unblocks. **Plus** a DB-backed round-trip test (`TestPolicyRulesRoundTrip`, testcontainers) that `CreatePolicy` → `GetPolicy` and asserts the rule comes back with its `Condition`/`Effect`/`Priority` intact — the only test that can catch the column-mapping regression that caused this whole defect (the in-memory tests cannot).

### 3. End-to-end verification (live, not committed)
On the box: `POST /api/v1/governance/policies` (a `timebound` policy with a rule whose hours exclude "now") → `POST /policies/:id/evaluate` with a context → assert `allowed:false`; flip a condition → `allowed:true`. This proves `GetPolicy` now feeds the evaluators. Confirm the doctor's `domain-presence` governance check flips to `ok` once a policy exists.

**No seed migration.** A fresh install legitimately has zero policies (the operator authors them); the doctor's "governance has no records" is an accurate informational nudge, not a defect. We do not force an example policy on every deployment.

### 1b. Authenticate the access→governance `/evaluate` call (discovered during live verification)

Live verification surfaced a second, more fundamental break the original scope missed: the access-proxy calls `POST /api/v1/governance/policies/:id/evaluate` (`internal/access/service.go` `evaluatePolicies`) with **no `Authorization` header**, while that route is behind `openIDXAuthMiddleware`, which requires a valid RS256 user JWT. The running governance returns **401** to the unauthenticated call; `evaluatePolicies` then reads the 401 body as `allowed:false` and the proxy **fails closed** — so attaching *any* policy to a route would deny *all* traffic to it, regardless of the rules. Loading the rules (1) is necessary but not sufficient; without auth the evaluators never run.

Fix (chosen approach — internal shared-secret header):
- Add `InternalServiceToken` to the shared config (`internal_service_token` / `INTERNAL_SERVICE_TOKEN`), read by every participating service. Empty disables the path (JWT-only).
- `openIDXAuthMiddleware` accepts a matching `X-Internal-Token` (constant-time compare) **only** on the `/evaluate` endpoints — scoped so a leaked token can't drive user-facing governance operations. The org is resolved by the existing global `TenantResolver` (`X-Org-ID` / `DefaultOrgFallback`), which runs before the group's auth middleware. Single-default-org installs resolve the default org; multi-tenant org-passing from the proxy is a follow-on (the proxy's `ProxyRoute`/`ProxySession` carry no org id today).
- `evaluatePolicies` sends `X-Internal-Token` and treats a non-200 as a *visible* error (logged, fails closed) rather than a silent deny.

## Out of scope (follow-on)
- G2 (register or delete the unused `ZTPolicyHandler` / `zt_policies`).
- A denial `reason` in the `/evaluate` response (the contract stays `{allowed, step_up_required}`).
- Rewriting/expanding the evaluators or the `policies.rules` dead JSONB column.
- Devices D2/D3.

## Verification checklist
- `go build/vet`, `go test ./internal/governance/` green (incl. the new per-type tests).
- Live: a `timebound` policy created via the API now denies via `/evaluate` (GetPolicy loads its rule); doctor governance presence → ok with a policy present.
