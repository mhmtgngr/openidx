# Device posture bridge (D1) — implementation plan

> Executed inline (focused slice). Spec: `docs/superpowers/specs/2026-06-26-device-posture-bridge-design.md`.

**Goal:** Make the device-posture chain functional end-to-end by writing `device_posture_results` from `HandleReport` and keying enforcement reads on the `ziti_identities.id` uuid.

## Tasks

### Task 1 — Migration v50 (upsert key) + init-db parity
- Create `internal/migrations/sql_v50.go`: up = `CREATE UNIQUE INDEX IF NOT EXISTS device_posture_results_identity_check ON device_posture_results (identity_id, check_id);`, down = `DROP INDEX IF EXISTS device_posture_results_identity_check;`.
- Register v50 in `internal/migrations/loader.go`.
- Mirror the index in `deployments/docker/init-db.sql` near the `device_posture_results` table.

### Task 2 — Reader fix (`internal/access/context_evaluator.go`)
- Change the identity resolution from `SELECT ziti_id …` to `SELECT id …` (uuid); rename the local to `identityUUID`. Pass it to `EvaluateIdentityPosture`. No other reader change (the function only uses it for the `device_posture_results` query).

### Task 3 — The bridge (`internal/access/agent_api.go`)
- Add `(h *AgentAPIHandler) bridgePostureResult(ctx, agentID, checkType, status, details, expiresAt)` (or fold inline) that, per reported result:
  1. resolve `identity_id` uuid: `SELECT zi.id FROM ziti_identities zi JOIN enrolled_agents ea ON ea.enrolled_by_user_id = zi.user_id WHERE ea.agent_id=$1 LIMIT 1` — skip+debug-log if none.
  2. resolve `check_id` + `org_id`: `SELECT id, org_id FROM posture_checks WHERE check_type=$1 AND enabled ORDER BY id LIMIT 1` — skip if none.
  3. upsert: `INSERT INTO device_posture_results (id, identity_id, check_id, passed, details, checked_at, expires_at, org_id) VALUES (gen_random_uuid(),$1,$2,$3,$4,NOW(),$5,$6) ON CONFLICT (identity_id, check_id) DO UPDATE SET passed=EXCLUDED.passed, details=EXCLUDED.details, checked_at=NOW(), expires_at=EXCLUDED.expires_at`.
  `passed = status == "pass"`. Best-effort (warn on error; never fail the report).
- Call it in `HandleReport` right after each `agent_posture_results` insert (same loop, same `r`).

### Task 4 — Doctor devices presence (`internal/access/health_checks.go`)
- In `domain-presence` detect, replace `SELECT count(*) FROM devices` with `SELECT count(*) FROM known_devices`.

### Task 5 — Verify (live, synthesized)
Seed a user→ziti_identity, an enrolled_agent (enrolled_by_user_id=that user), an enabled posture_check; drive a report; assert one `device_posture_results` row with the right uuid identity_id + check_id; `EvaluateIdentityPosture` returns it; re-report upserts (no dup). `go build/vet/test`.

## Verification checklist
- `go build ./...`, `go vet`, `go test ./internal/access/ ./internal/migrations/` green.
- Migration v50 applied (live: apply the index SQL directly, box has AUTO_MIGRATE off).
- Synthesized end-to-end bridge works; doctor `domain-presence` devices counts `known_devices`.
