# PAM M4 — Session assurance

> Milestone M4 of the [PAM roadmap](2026-07-02-pam-architecture-roadmap.md). Adds assurance
> over privileged sessions and privileged entitlements: keystroke/command **transcripts**,
> **live monitoring** of active sessions, **session-end detection**, and **attestation** of
> vault/rotation entitlements. Scope confirmed with the user: **all three** (+ session-end
> detection). Also fixes an M3 recording data-loss bug found during design.

## Context

M3 brokers Guacamole sessions with server-side credential injection, native recording,
force-terminate, and a `guacamole_sessions` table. M4 makes those sessions **auditable and
governed**: what was typed (transcript), who's connected right now (live monitor), reliable
end-of-session marking, and periodic review of who may access which secret (attestation).

**M3 bug this fixes (data loss):** `recordGuacSession` stored `recording_path` = the shared
recording *directory* (`s.config.GuacamoleRecordingPath`), and `sweepExpiredGuacRecordings`
runs `os.RemoveAll(recording_path)` — so purging one expired session **deletes every
recording**. guacd writes the file to `<dir>/<recName>` (recName = `connID-<ms>`) but recName
was never persisted. Fix: persist the full **file** path per session and operate on it.

## Design — five parts

### 1. Recording-path fix (data-loss) + transcript columns — migration v60

- The connect handler already computes `recName` (`guacamole.go:488`). Change it to pass the
  **full file path** `filepath.Join(recPath, recName)` to `recordGuacSession`, so
  `guacamole_sessions.recording_path` holds the specific file. `sweepExpiredGuacRecordings`'s
  `os.RemoveAll` then removes only that file. (Guard: never `RemoveAll` a path equal to the
  configured recordings root.)
- Migration **v60**: add `transcript_path TEXT`, `transcript_generated_at TIMESTAMPTZ` to
  `guacamole_sessions` (idempotent `ADD COLUMN IF NOT EXISTS`; no new table, no belt change).

### 2. Session-end detection (pure Go)

guacd doesn't notify OpenIDX when a user disconnects, so `status='active'` rows leak. A new
sweep (in the retention enforcer's ticker, `remote_support_retention.go`) reconciles active
sessions against Guacamole:
- `active := guacamoleClient.ListActiveSessions(ctx)` → set of `(connectionIdentifier,
  username)` currently live.
- For each `guacamole_sessions` row `status='active'` **older than a grace period**
  (`started_at < NOW() - 2m`, so freshly-prepped sessions the user hasn't opened yet aren't
  falsely ended), join to its `guacamole_connections.guacamole_connection_id` + the user's
  username; if not in the live set → `UPDATE … SET status='ended', ended_at=NOW()`. Audit
  `guacamole.session_ended_detected`. Opportunistically capture `guac_session_uuid` when a
  match exists (for future correlation).

### 3. Transcript pipeline (guaclog)

A new sweep generates a keystroke/command transcript for ended, recorded sessions:
- Select `guacamole_sessions` where `status IN ('ended','terminated')`, `recording_path`
  set + not purged, `transcript_path IS NULL`.
- If `guaclog` is available (`exec.LookPath("guaclog")` — **best-effort**, so absent tooling
  is a clean no-op, not a failure), run `guaclog <recording_file>` (writes
  `<recording_file>.txt`), then `UPDATE … SET transcript_path=$1, transcript_generated_at=NOW()`.
  guaclog runs under `exec.CommandContext` with a timeout; never logs the transcript content.
- Serve: `GET /api/v1/access/guacamole/sessions/:id/transcript` (admin) streams the transcript
  file (org-scoped via the session's connection→route→org). The retention sweep also removes
  the transcript file alongside the recording on purge.
- **Deployment:** add `guaclog` (from guacamole-server) to the access-service image; document
  that the box host needs `guaclog` on PATH. Because generation is `LookPath`-gated, the
  feature is inert until the binary is present — no runtime breakage.

### 4. Live monitor (Guacamole connection sharing)

- Add `GuacamoleClient.ShareActiveConnection(ctx, activeConnID) (shareURL string, err error)`
  — mints a **read-only** sharing link for an active connection via Guacamole's sharing-profile
  REST API. `POST /api/v1/access/guacamole/sessions/:id/share` (admin) returns the URL; audit
  `guacamole.session_shared`. If the deployed Guacamole lacks the sharing API, the call returns
  a clear error and the admin falls back to the existing active-session list
  (`GET /guacamole/sessions`) — documented, no hard dependency.

### 5. Attestation of privileged entitlements (pure Go/SQL, no migration)

Extend the live attestation engine (`internal/admin/attestation.go`):
- Add campaign types `vault_access` and `rotation_policy` to the validated set.
- `generateAttestationItems`: 
  - `vault_access` → enumerate non-expired `vault_access_grants` (org-scoped) into
    `attestation_items` (`resource_type='vault_access'`, `resource_id=<grant id>`,
    `resource_name=<secret name>:<actions>`, `user_id=<principal_id>`).
  - `rotation_policy` → enumerate `credential_rotation_policies` (org-scoped) into items
    (`resource_type='rotation_policy'`, `resource_id=<policy id>`, name=`<secret>:<connector>`).
- Revoke remediation (the `decision='revoked'` switch): 
  - `vault_access` → `DELETE FROM vault_access_grants WHERE id=$1 AND org_id=$2`.
  - `rotation_policy` → `UPDATE credential_rotation_policies SET enabled=false WHERE id=$1
    AND org_id=$2` (disable, don't drop — preserves history).
  Fail-closed (item stays pending if remediation errors), matching the existing pattern. Audit
  the revoke.
- No schema change (reuses `attestation_items`; `resource_id` is a generic UUID). Note the
  pre-existing gap that attestation tables lack `org_id`/RLS — out of scope here; enumeration
  + remediation are org-scoped in the handler via `orgctx`.

## Cross-cutting

- **Security:** transcripts/recordings are session artifacts (may contain sensitive keystrokes)
  — the transcript endpoint is admin-guarded + org-scoped; guaclog output is never logged;
  share links are read-only + audited. Revoke remediation is audited.
- **RLS/orgscope:** the two background sweeps run under bypass-RLS (cross-org) with
  `//orgscope:ignore`; handler queries are org-scoped.
- **No credential exposure** changes (M4 doesn't touch injection).
- **Migration discipline:** v60 is plain `ADD COLUMN IF NOT EXISTS` (no `DO $$`), mirrored to
  init-db.sql, `TestInitDBParity` green.

## Testing

- **Unit:** the recording-path join (full file path, and the RemoveAll-root guard);
  transcript path derivation + `LookPath` gating (skip when absent); the attestation
  enumerate/revoke SQL shape via the existing pattern; sharing-URL construction.
- **Integration:** v60 columns exist; session-end detection marks a stale active row ended
  (with a mocked/empty active set) and leaves a fresh one active; a `vault_access` campaign
  enumerates a seeded grant and a revoke deletes it; RLS isolation on the new queries.
  guaclog/live-monitor exercised via stubs (no real guacd/guaclog in CI).
- Gates: build, vet, gofmt, `orgscope -fail ./internal`, golangci-lint, govulncheck,
  `go test`, integration compiles under `-tags=integration`.

## Verification (box)

Open + close a recorded Guacamole session → within a sweep the row flips to `ended` → a
`.txt` transcript appears (if guaclog installed) and downloads via the endpoint; while active,
`POST …/share` returns a read-only URL. Create a `vault_access` attestation campaign → it
lists the seeded grants → revoking one deletes the grant (the user can no longer reveal).

## Out of scope
- Ziti/BrowZer session assurance (different data plane).
- A transcript/recording *player* UI.
- Adding `org_id`/RLS to the attestation tables (pre-existing gap).
- M5 rotation connectors (next milestone).

## Critical files
- Migration: `internal/migrations/sql_v60.go` (+ loader + init-db.sql).
- Modify: `internal/access/guacamole.go` (recording full-file path; `ShareActiveConnection`),
  `internal/access/guacamole_sessions.go` (share + transcript-download handlers, session-end
  helper), `internal/access/remote_support_retention.go` (session-end + transcript sweeps;
  RemoveAll-root guard), `internal/access/service.go` (routes), `internal/admin/attestation.go`
  (vault_access + rotation_policy types + revoke), the access-service Dockerfile (guaclog).
- New: `test/integration/session_assurance_test.go`.
- Reuse: `GuacamoleClient` + `ListActiveSessions` (`guacamole.go`), the retention-sweep ticker
  (`remote_support_retention.go`), the attestation engine (`admin/attestation.go`),
  `vault.RevokeGrantForPrincipal`.
