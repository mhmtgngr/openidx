# Governance policy engine (governance slice G1) — design

## Context

"Wire up governance." Exploration showed the policy engine is **already built but starved**: the five per-type evaluators (`separation_of_duty`, `risk_based`, `timebound`, `location`, `conditional_access`) are fully implemented (`internal/governance/service.go:776–1038`) and operate on `policy.Rules[].Condition`. The access-proxy already calls `POST /policies/:id/evaluate` (`internal/access/service.go:2483` `evaluatePolicies`) for every route with `policy_ids`, sending a rich context (`user_id, roles, ip, time, path, method, route, risk_score, device_trusted, auth_methods, location, …`) and honoring `{allowed, step_up_required}`.

**The one blocking bug:** `GetPolicy` (`service.go:588`) selects only the `policies` row and **never loads `policy_rules`**, so `policy.Rules` is always empty. `EvaluatePolicy → GetPolicy → <evaluator>` then loops over zero rules and returns `true` (allow). `handleEvaluatePolicy`'s step-up loop has the same problem. `ListPolicies` (`service.go:609`) already loads rules correctly — so the rule-loading query is proven.

Settled (no work): the `inline_policy` DSL (`internal/access/policy_dsl.go`) is a separate, already-working mechanism and **cannot be reused** here (it lives in `internal/access`, which imports `internal/governance` → reusing it would be a circular import). G1 keeps the existing per-type evaluators.

## Design

### 1. Fix `GetPolicy` to load rules (the core change)
After loading the `policies` row, load its `policy_rules` exactly as `ListPolicies` does (same SELECT + the same `conditions` JSONB → `rule.Condition` unmarshal), and set `policy.Rules`. This single change activates all five evaluators **and** the step-up loop. Reconcile the policy_rules column names against what `ListPolicies` actually queries (there's an apparent `rule_type/conditions/actions` vs `condition/effect/priority` discrepancy) by reusing `ListPolicies`' working query verbatim — extract it into a shared `loadPolicyRules(ctx, policyID, orgID) ([]PolicyRule, error)` helper used by both `GetPolicy` and `ListPolicies` (DRY; one query to keep correct).

### 2. Verify the evaluators (unit tests)
The evaluators have never run against loaded rules. Add a focused test per type that builds a `Policy` with `Rules` + an evaluation `request` map and asserts the decision:
- `timebound`: deny outside `start_hour..end_hour` / disallowed weekday; allow inside.
- `separation_of_duty`: deny when the user holds ALL `conflicting_roles`; allow otherwise.
- `location`: deny when the IP matches no `allowed_ip_prefixes`.
- `risk_based`: deny when accumulated risk ≥ `risk_threshold`.
- `conditional_access`: deny + `step_up_required` when `require_mfa`/`device_trust_required`/`max_risk_score` fail.
These call the evaluators directly (in-memory `Rules`), so they don't need a DB and pin the logic the `GetPolicy` fix unblocks.

### 3. End-to-end verification (live, not committed)
On the box: `POST /api/v1/governance/policies` (a `timebound` policy with a rule whose hours exclude "now") → `POST /policies/:id/evaluate` with a context → assert `allowed:false`; flip a condition → `allowed:true`. This proves `GetPolicy` now feeds the evaluators. Confirm the doctor's `domain-presence` governance check flips to `ok` once a policy exists.

**No seed migration.** A fresh install legitimately has zero policies (the operator authors them); the doctor's "governance has no records" is an accurate informational nudge, not a defect. We do not force an example policy on every deployment.

## Out of scope (follow-on)
- G2 (register or delete the unused `ZTPolicyHandler` / `zt_policies`).
- A denial `reason` in the `/evaluate` response (the contract stays `{allowed, step_up_required}`).
- Rewriting/expanding the evaluators or the `policies.rules` dead JSONB column.
- Devices D2/D3.

## Verification checklist
- `go build/vet`, `go test ./internal/governance/` green (incl. the new per-type tests).
- Live: a `timebound` policy created via the API now denies via `/evaluate` (GetPolicy loads its rule); doctor governance presence → ok with a policy present.
