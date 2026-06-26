# Device posture bridge (devices slice D1) — design

## Context

First slice of "wire up the devices domain." Exploration showed the device-posture chain is *almost* complete — only one link is missing and one is mis-keyed:

```
enroll ✓ → agent POSTs results → agent_posture_results ✓
        → [BRIDGE: missing] → device_posture_results → enforcement reads it ✓ → access decision ✓
```

Two defects break it end to end:
1. **Missing bridge.** `HandleReport` (`internal/access/agent_api.go`) writes `agent_posture_results` (keyed by `agent_id` + `check_type`), but **nothing writes `device_posture_results`** (keyed by `identity_id` uuid + `check_id` uuid) — which is what posture enforcement reads. So every posture check fails-closed for lack of data.
2. **Broken identity key.** The enforcement reader (`context_evaluator.go:73`) resolves the session user's `ziti_id` (controller **varchar**, e.g. `jHnQvBROMH`) and queries `device_posture_results.identity_id`, a **uuid** column → type mismatch; the read can't succeed even with data. It must key on `ziti_identities.id` (uuid). `EvaluateIdentityPosture(identityID)` uses the id only for that DB query (no controller call), so changing the key is safe.

Everything else is already wired: enrollment (`enrolled_agents`, tokens), agent reporting, `posture_checks` CRUD, and the enforcement gates in `context_evaluator`/`posture.go`.

## Design

### 1. Bridge — `HandleReport` also writes `device_posture_results`
After persisting each reported result to `agent_posture_results`, upsert a `device_posture_results` row:
- **`identity_id` (uuid)** = `ziti_identities.id` resolved via the agent's **enrolling user**: `enrolled_agents.enrolled_by_user_id → ziti_identities.user_id → .id`. This is deliberately the *user's* Ziti identity, because the reader resolves posture by the session user's identity (`ziti_identities WHERE user_id = session.UserID`), so the bridged row is the one enforcement looks up. Skip + debug-log if the agent has no linked user / the user has no Ziti identity.
- **`check_id` (uuid)** = `posture_checks.id WHERE check_type = <report check_type> AND enabled` (deterministic: lowest id if several). Skip a result whose `check_type` matches no posture_check.
- **`passed`** = `status == "pass"`; **`details`** = the report details; **`checked_at`** = now; **`expires_at`** = the report's `expires_at`; **`org_id`** = the posture_check's `org_id`.
- **Upsert** on `(identity_id, check_id)` — one latest row per check (history stays in `agent_posture_results`).

### 2. Reader fix — key on the uuid
`context_evaluator.go:73`: change `SELECT ziti_id FROM ziti_identities WHERE user_id=$1` to `SELECT id …` (uuid) and pass that uuid to `EvaluateIdentityPosture`. (Rename the local `zitiIdentityID` for clarity.)

### 3. Migration v50 — upsert key
`CREATE UNIQUE INDEX IF NOT EXISTS device_posture_results_identity_check ON device_posture_results (identity_id, check_id)`. The table is empty, so this is safe; mirror it in `init-db.sql` for fresh deploys. (`DISTINCT ON (check_id) … ORDER BY check_id, checked_at DESC` in the reader already tolerates duplicates; the unique index keeps it to one row per check and enables `ON CONFLICT`.)

### 4. Doctor fix — devices presence check
The Relations Doctor's `domain-presence` check counts a non-existent `devices` table. Point it at the real device inventory: `SELECT count(*) FROM known_devices` (the canonical device registry). So "devices wired up" reports `ok` once devices exist.

## Verification
No agents are enrolled on the box, so verify end-to-end by synthesizing:
1. Seed a `ziti_identities` row for a user, an `enrolled_agents` row linked to that user (`enrolled_by_user_id`), and an enabled `posture_checks` row.
2. Drive a report through `HandleReport` (or its persistence path) with that check's `check_type`.
3. Assert a `device_posture_results` row appears with `identity_id` = the user's `ziti_identities.id` (uuid) and the right `check_id`/`passed`.
4. `EvaluateIdentityPosture(<that uuid>)` returns the result; a re-report upserts (no duplicate row).
- `go build/vet`, `go test ./internal/access/ ./internal/migrations/`; migration replay clean.

## Out of scope (follow-on specs)
- D2 (populate `ProxySession.DeviceTrusted` at session creation), D3 (`device_trust_requests` approval workflow), the governance slices (G1 policy engine, G2 ZTPolicyHandler). The `device_trust`/`posture_check_types` orphan tables stay as-is.
