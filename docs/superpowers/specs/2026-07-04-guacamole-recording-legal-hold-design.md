# Guacamole recording legal-hold

**Goal:** The recording-retention purger deletes expired **Guacamole** session recordings without
honoring any legal-hold — because holds can only be placed on remote-support sessions today. Extend
legal-hold to Guacamole sessions so a held recording is never purged.

**Verified current state (2026-07-04):**
- `internal/access/remote_support_retention.go:308 sweepExpiredGuacRecordings` runs under the
  background retention enforcer, selects ended/terminated `guacamole_sessions` with a
  `recording_path` and `recording_purged_at IS NULL`, `os.RemoveAll`s the recording, and stamps
  `recording_purged_at`. Its own comment (lines 319–320) flags the gap: *"recording_legal_holds.session_id
  references remote_support_sessions, not guacamole_sessions. Guacamole recording legal-hold is
  therefore out of scope."*
- **Legal-hold already exists for remote-support** (`recording_legal_holds` table, migration v42;
  `remote_support_legal_hold.go` place/release/list endpoints; the remote-support purge query skips
  held sessions). This is the pattern to mirror.
- `guacamole_sessions` (migration v59) has `org_id`, `recording_path`, `recording_purged_at`, `status`.
- `recording_legal_holds` is **not** RLS-belted; tenancy flows through the session FK + org-scoped
  handler queries. Migration ceiling is **v67**; `init-db.sql` is retired (migrations are the sole
  schema source — no init-db mirror, no parity test).

## Design (mirror the remote-support legal-hold, for Guacamole)

A **separate** `guacamole_recording_legal_holds` table (not a polymorphic column on
`recording_legal_holds`) — its FK must cascade to `guacamole_sessions`, and one table can't FK to
two parents; a parallel table keeps the clean per-type FK + `ON DELETE CASCADE` and doesn't disturb
the working remote-support path.

### 1. Migration v68 (`internal/migrations/sql_v68.go` + loader registration)
```sql
CREATE TABLE IF NOT EXISTS guacamole_recording_legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL,
    reason          TEXT NOT NULL,
    placed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    placed_by       UUID,
    released_at     TIMESTAMPTZ,
    released_by     UUID,
    released_reason TEXT,
    CONSTRAINT guac_rec_legal_holds_session_fk
        FOREIGN KEY (session_id) REFERENCES guacamole_sessions(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_guac_rec_legal_holds_lookup
    ON guacamole_recording_legal_holds(session_id) WHERE released_at IS NULL;
GRANT SELECT, INSERT, UPDATE, DELETE ON guacamole_recording_legal_holds TO openidx_app;
```
Plain `GRANT` (no `DO $$` block — the splitSQL lesson); `openidx_app` exists by v68 (v53 created it).
Not RLS-belted (mirrors `recording_legal_holds`). Down: `DROP TABLE IF EXISTS guacamole_recording_legal_holds`.

### 2. Gate the purger (`sweepExpiredGuacRecordings`)
Add to the candidate-selection query:
```sql
   AND NOT EXISTS (
        SELECT 1 FROM guacamole_recording_legal_holds h
         WHERE h.session_id = guacamole_sessions.id AND h.released_at IS NULL
   )
```
so a session under an active hold is never selected for purge. Update the stale comment (no longer
out of scope). This is the security-critical change — a held recording must not be deleted.

### 3. Legal-hold endpoints (mirror `remote_support_legal_hold.go`)
On the access `Service` (the type that owns the guac session admin handlers in
`guacamole_sessions.go`), add place/release/list, mounted alongside the existing
`/api/v1/access/guacamole/sessions/...` admin routes:
- `POST   /guacamole/sessions/:id/legal-hold`  → insert a hold (reason required); **409** if an active
  hold already exists (mirror remote-support). `placed_by` from the auth context.
- `DELETE /guacamole/sessions/:id/legal-hold`  → stamp `released_at`/`released_by`/`released_reason`
  on the active hold.
- `GET    /guacamole/sessions/:id/legal-holds` → list active + historical holds.
Each handler must confirm the session is visible under the caller's org (the `guacamole_sessions`
query is org-scoped via RLS), so one org can't place holds on another's session. Audit each action
(mirror the remote-support `h.audit(...)` calls: `guacamole.legal_hold_placed` / `_released`).

## Testing / verification
- **Integration (authoritative — the purge gate):** throwaway DB → migrate → seed a `guacamole_sessions`
  row with a `recording_path` (status `ended`, past retention) + an active hold → run the guac sweep →
  assert `recording_purged_at` stays NULL AND the file is NOT removed. Release the hold → run again →
  assert purged. This proves legal-hold protects the recording.
- Endpoint tests: place → 201; place again → 409; release → 200 + `released_at` set; list → shows both.
- `go build ./...`, `go vet`, `gofmt`; migration applies clean on top + from-empty; CI green.
- Optional box smoke: create a guac session row + hold, run the sweep under bypass-RLS, assert the
  held recording is skipped (mirrors prior box smokes; throwaway rows cleaned up).

## Scope / risk
- Single PR: migration v68 + purger gate + 3 endpoints + tests. `internal/access` + `internal/migrations`.
- Migration is additive (new table); no change to existing tables. Box deploy needs the migration
  (v67→v68) — unlike the recent releases, this one DOES touch the schema.
- Out of scope: a per-session guac `recording_retention_days` override (the sweep notes guac has none —
  a separate enhancement); admin-console UI for placing holds (frontend follow-up); backfilling holds.

## Open questions (resolve at impl)
1. Where exactly the guac admin routes are registered (find the `RegisterRoutes` mounting
   `guacamole/sessions/...`) to add the three legal-hold routes consistently.
2. The auth-context helper for `placed_by`/`released_by` (reuse whatever the guac admin handlers or
   remote-support legal-hold use).
