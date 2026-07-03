# Reconcile referenced-but-uncreated tables (readiness W2.8)

> Second item of Workstream 2. Four tables are **referenced by code but created by
> neither a migration nor `init-db.sql`** — the same latent-500 class that the M2a
> `jit_grants` fix closed. Migration **v62** creates them to match the code's exact
> usage, mirrored into `init-db.sql`.

## Verification of the survey (done, repo-authoritative)

For each candidate: is it in `init-db.sql`? in any migration? referenced by code?

| Candidate | init-db | migration | code | Verdict |
|---|---|---|---|---|
| `admin_console_settings` | ✗ | ✗ | `internal/admin/handlers/settings.go` | **missing → create** |
| `auth_contexts` | ✗ | ✗ | `internal/admin/continuous_auth.go` | **missing → create** |
| `breach_alerts` | ✗ | ✗ | `internal/admin/ibdr.go` | **missing → create** |
| `breach_incidents` | ✗ | ✗ | `internal/admin/ibdr.go` | **missing → create** |
| `access_stats` | ✗ | ✗ | `internal/admin/ai_policy_recommendations.go` | **FALSE POSITIVE** — it is a CTE (`WITH access_stats AS …`), not a table. No action. |

None of the four self-create (no `CREATE TABLE` in the code), so the endpoints that touch them
500 today. (On the box these are absent for the same reason; a `to_regclass` check there would
confirm, but the repo check is authoritative — a table in neither source cannot exist unless the
code made it, and it doesn't.)

## Design

Follow the **M2a `jit_grants` reconcile precedent exactly**: create the tables to match the code's
exact column/type usage; **not** under the v37 RLS belt (the code does not org-scope these — they
carry no `org_id` in any query; adding `org_id`/RLS is a separate hardening follow-up, tracked with
the W2.10 `jit_grants`/`request_approval_chains` item). Plain `GRANT` to `openidx_app` (no `DO $$`
block — splitSQL constraint). Register in `loader.go` as **v62**. Mirror verbatim into
`deployments/docker/init-db.sql` so `TestInitDBParity` stays green.

### Schemas (derived from every query + the Go structs)

**`admin_console_settings`** (settings.go — `ON CONFLICT (key)`):
`key TEXT PRIMARY KEY`, `value JSONB NOT NULL DEFAULT '{}'`, `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `updated_by TEXT`.

**`auth_contexts`** (continuous_auth.go — looked up/updated by `session_id`):
`session_id UUID PRIMARY KEY`, `user_id UUID`, `auth_time TIMESTAMPTZ`, `auth_method TEXT`,
`auth_strength TEXT`, `current_risk_score DOUBLE PRECISION`, `device_fingerprint TEXT`,
`ip_address TEXT`, `location TEXT`, `user_agent TEXT`, `metadata JSONB NOT NULL DEFAULT '{}'`,
`updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`. (No FK on session_id — the code treats it as a
lookup key and a context row may exist independent of a live `sessions` row.)

**`breach_incidents`** (ibdr.go — id is `uuid.New().String()`; arrays are `[]string`; confidence
`float64`; indicators `json.RawMessage`):
`id UUID PRIMARY KEY DEFAULT gen_random_uuid()`, `type TEXT`, `severity TEXT`, `status TEXT`,
`title TEXT`, `description TEXT`, `affected_user_ids TEXT[]`, `affected_sessions TEXT[]`,
`detection_method TEXT`, `first_detected_at TIMESTAMPTZ`, `last_activity_at TIMESTAMPTZ`,
`confidence DOUBLE PRECISION`, `indicators JSONB`, `quarantine_action TEXT`,
`created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`.

**`breach_alerts`** (ibdr.go):
`id UUID PRIMARY KEY DEFAULT gen_random_uuid()`, `incident_id UUID REFERENCES breach_incidents(id) ON DELETE CASCADE`,
`type TEXT`, `severity TEXT`, `message TEXT`, `user_id UUID`, `session_id TEXT`, `ip_address TEXT`,
`created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, `acknowledged BOOLEAN NOT NULL DEFAULT false`,
`acked_at TIMESTAMPTZ`, `acked_by TEXT`.
(`incident_id` FK → create `breach_incidents` first in the same migration. `session_id` kept TEXT —
the alert copies `AffectedSessions[0]`, a free-form string, not necessarily a `sessions.id`.)

Indexes: `breach_alerts(incident_id)`, `breach_alerts(acknowledged, created_at DESC)`,
`breach_incidents(status, created_at DESC)`.

Down: `DROP TABLE IF EXISTS` the four (alerts before incidents for the FK), CASCADE.

## Testing
- `go build ./...`, `go vet`, `gofmt`, `go run ./tools/orgscope -fail ./internal` (must stay clean —
  these tables are intentionally not org-scoped, so the linter should not flag them; if it does,
  reconcile per its guidance).
- `go test ./internal/migrations/ -run TestInitDBParity` green (the four tables now exist in both
  the migration set and init-db, closing the parity gap for them).
- Migration applies on top of init-db and on a fresh init-db (CI Integration Tests).

## Out of scope
`org_id`/RLS on these tables and on `jit_grants`/`request_approval_chains` (W2.10 hardening);
column-level parity guard + `ziti_certificates` (W2.9). This item only makes the referenced tables
exist so their endpoints stop 500ing.

## Critical files
- New: `internal/migrations/sql_v62.go`; edit `internal/migrations/loader.go` (register v62),
  `deployments/docker/init-db.sql` (mirror the four CREATE TABLEs + indexes + grant).
- Reuse anchor: the M2a `jit_grants` reconcile (migration v58, `internal/migrations/sql_v58.go`).
