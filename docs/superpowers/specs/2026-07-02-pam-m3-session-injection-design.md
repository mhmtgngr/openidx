# PAM M3 — Privileged session brokering with credential injection

> Milestone M3 of the [PAM roadmap](2026-07-02-pam-architecture-roadmap.md). Turns the
> existing Guacamole brokering into full PAM privileged-session access: the target
> credential is injected **server-side** (the user never sees it), sessions are
> **approval-gated**, **recorded**, and **force-terminable**. Scope confirmed with the
> user: core injection **plus** all three extras. Credential model: the vault secret is
> the password/key; the username lives on the connection config.

## Context

OpenIDX already brokers RDP/SSH/VNC via Apache Guacamole (`internal/access/guacamole.go`):
a route is provisioned as a Guacamole connection, and `handleGuacamoleConnect`
(`guacamole.go:388`) returns a client URL + token to the browser. But connection
**parameters carry no target credentials** — users must authenticate to the target
themselves, and there's no approval gate, no session recording, and no force-terminate for
Guacamole. M1/M1b/M2 gave us an encrypted vault, rotation, and JIT checkout; M3 makes
brokered sessions use them so a privileged session can be opened **without ever exposing
the credential to the human**.

`internal/vault` is a library over the shared DB + KEK, so access-service instantiates its
own in-process `vault.Service` (same bootstrap as governance-service in M2b) — no
cross-service HTTP.

## Design — four capabilities

### 1. Credential injection (foundation)

- **Association:** add `vault_secret_id UUID REFERENCES vault_secrets(id) ON DELETE SET NULL`
  and `inject_username VARCHAR(255)` to `guacamole_connections` (the natural join — it
  already maps `route_id → guacamole_connection_id`). The username is an account name (not
  sensitive); the password/key is the vault secret. Rotation (M1b) changes only the secret.
- **Injection point:** in `handleGuacamoleConnect` (`guacamole.go:388`), after resolving
  the connection, if it has a `vault_secret_id`:
  - `cred, err := s.vaultSvc.Use(orgctx.WithBypassRLS(ctx), secretID)` — system read; the
    plaintext stays server-side, `defer zero(cred)`.
  - `s.guacamoleClient.UpdateConnection(connID, …, params{ "username": inject_username,
    "password": string(cred) })` (protocol-appropriate: `password` for rdp/vnc/ssh,
    `private-key` when the secret type is `ssh_key`).
  - Return the connect URL/token to the browser as today — **the credential is never in the
    response**. Audit `guacamole.credential_injected` (secret_id, connection, user; no value).
- **Wiring:** access-service builds `vault.KeyringFromConfig(cfg)` → `vault.NewService(...)`
  → `accessService.SetVaultService(...)`, fail-closed on missing KEK (mirrors M2b). If a
  connection has no `vault_secret_id`, behaviour is unchanged (no injection).

### 2. Pre-session approval gate

Self-contained in access-service (session approval is ephemeral and per-connection — lighter
than the governance role/credential grants; keeping it local avoids cross-service coupling).

- Add `require_approval BOOLEAN NOT NULL DEFAULT false` to `guacamole_connections`.
- New table `guacamole_session_requests` (org-scoped, RLS belt):
  `id, org_id, connection_id/route_id, requester_id, reason, status
  (pending|approved|denied|consumed|expired), approver_id, decided_at, expires_at,
  created_at`.
- Endpoints (admin-guarded group): `POST /guacamole/connections/:routeId/request` (create,
  by the would-be user), `POST /guacamole/session-requests/:id/approve` + `/deny` (admin),
  `GET /guacamole/session-requests` (list pending).
- **Gate:** `handleGuacamoleConnect` — if the connection has `require_approval=true`, require
  an `approved`, unexpired, unconsumed request for `(connection, requester)`; on connect,
  mark it `consumed`. No approval / expired → 403. Connections without `require_approval`
  are unaffected.

### 3. Force-terminate (Guacamole)

- New `POST /guacamole/sessions/:id/terminate` (admin), body `{reason}`: call Guacamole's
  active-sessions API (`PATCH /session/data/<ds>/activeConnections` remove, or
  `DELETE …/activeConnections/<uuid>`) via `GuacamoleClient`; audit
  `guacamole.session_terminated` with reason. Mirrors `handleDeleteZitiSession`
  (`ziti_session_handlers.go:114`). Also expose `GET /guacamole/sessions` (list active)
  from Guacamole's active-connections endpoint for the admin console.

### 4. Session recording (Guacamole native)

- Enable guacd's built-in recording by injecting recording params on connect:
  `recording-path` (a shared volume guacd + access-service can read), `recording-name`
  (`<connection>-<sessionid>-<ts>`), `recording-include-keys=true`. guacd writes a
  session recording (Guacamole protocol dump) to that path.
- Track each recorded session in a new `guacamole_sessions` table (`id, org_id,
  connection_id, user_id, guac_session_uuid, recording_path, started_at, ended_at, status`).
- **Reuse the existing recording lifecycle:** the remote-support retention + legal-hold
  machinery (`remote_support_retention.go`, `remote_support_legal_hold.go`) already sweeps
  and holds recordings by org policy — extend its sweep to cover `guacamole_sessions`
  recordings (same `recording_retention_policies` + legal-hold tables), so Guacamole
  recordings inherit retention + legal hold without a parallel system.
- Recording is opt-in per connection (`record_session BOOLEAN DEFAULT false` on
  `guacamole_connections`) or on when a global/org policy requires it.

## Data model — migration v59

New Go migration `internal/migrations/sql_v59.go` (registered in `loader.go`, mirrored into
`init-db.sql`, `TestInitDBParity` green):

- `ALTER TABLE guacamole_connections ADD COLUMN vault_secret_id UUID REFERENCES
  vault_secrets(id) ON DELETE SET NULL`, `inject_username VARCHAR(255)`,
  `require_approval BOOLEAN NOT NULL DEFAULT false`, `record_session BOOLEAN NOT NULL
  DEFAULT false` (all idempotent `ADD COLUMN IF NOT EXISTS`).
- `guacamole_session_requests` and `guacamole_sessions` — both **org-scoped under the v37
  FORCE-RLS belt** (they carry `org_id` and hold sensitive access records). Copy the v56
  belt pattern (`pol_<t>_org_scope` + ENABLE/FORCE + `GRANT … TO openidx_app` as a **plain
  GRANT**, per the v56/v57 splitSQL lesson — no `DO $$` block).

## Cross-cutting

- **Security:** the injected credential is `[]byte`, `defer zero`'d, never logged, never in
  any HTTP response or audit `details`; `Use` runs under bypass with the org derived from
  the connection/route. Injection and every session action are audited to
  `unified_audit_events`.
- **RLS:** new tables org-scoped + FORCE; access-service queries via `orgctx`; the
  connect-time `Use` uses `WithBypassRLS` + the connection's org.
- **Config:** access-service gains the `VAULT_*` config (shared KEK) and a
  `GUACAMOLE_RECORDING_PATH` (the shared guacd volume).
- **Deploy note:** access-service now needs the same `ENCRYPTION_KEY`/`VAULT_KEK` as
  admin-api/governance, and guacd + access-service must share the recording volume.
- **Migration discipline:** plain `GRANT` (no `DO $$`), mirror to init-db.sql, parity green.

## Testing

- **Unit:** injection maps secret→password / ssh_key→private-key + username from config;
  the approval gate denies without an approved/unexpired/unconsumed request and consumes it
  on connect; force-terminate calls the Guacamole API with the reason; recording params are
  set only when `record_session`.
- **Integration:** v59 applies (init-db + on-top) + FORCE-RLS on the two new tables +
  `TestInitDBParity`; an approval request round-trip (request→approve→consume) with RLS
  isolation; a `guacamole_sessions` row is created and picked up by the retention sweep.
  Guacamole API calls are exercised via a stub/mock client (no live guacd in CI).
- Gates: build, vet, gofmt, `orgscope -fail ./internal`, golangci-lint, govulncheck,
  `go test`, integration compiles under `-tags=integration`.

## Verification (box)

Provision a Guacamole RDP route with `vault_secret_id` (a stored admin password),
`inject_username='administrator'`, `require_approval=true`, `record_session=true`. A user
requests → admin approves → user connects → the RDP session opens **without the user
entering/seeing the password** → a recording appears under the recording path and a
`guacamole_sessions` row exists → admin force-terminates with a reason → the session drops
and the audit trail shows request/approve/inject/terminate.

## Out of scope

- Ziti/BrowZer credential injection (the clientless data plane; separate initiative).
- SSH/DB/cloud rotation connectors (M5).
- A recording *player* UI (recordings are stored + retained; playback tooling is separate).

## Critical files

- Modify: `internal/access/guacamole.go` (injection in `handleGuacamoleConnect`, approval
  gate, recording params, `GuacConnection.VaultSecretID`/`InjectUsername`/flags,
  provisioning), `internal/access/service.go` (vault field + setter + new routes),
  `cmd/access-service/main.go` (construct + inject `vault.Service`, recording path),
  `internal/access/remote_support_retention.go` (extend sweep to `guacamole_sessions`),
  `internal/common/config/config.go` (`GUACAMOLE_RECORDING_PATH`; `VAULT_*` already exist).
- New: `internal/access/guacamole_sessions.go` (approval-request + force-terminate + session
  handlers), `internal/migrations/sql_v59.go`, `test/integration/guacamole_injection_test.go`.
- Reuse: `vault.Use` (`internal/vault/store.go`), `GuacamoleClient` (`guacamole.go`),
  `handleDeleteZitiSession` pattern (`ziti_session_handlers.go:114`), the
  retention/legal-hold pipeline (`remote_support_retention.go`, `remote_support_legal_hold.go`),
  the M2b vault-wiring bootstrap (`cmd/governance-service/main.go`).
