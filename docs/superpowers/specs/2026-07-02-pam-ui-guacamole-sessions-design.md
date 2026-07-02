# PAM UI — Guacamole Session admin page (readiness W1.3)

> Third slice of the readiness-finalization plan (Workstream 1: make the shipped PAM usable).
> The M3/M4 privileged-session brokering (pre-session approval gate, force-terminate, read-only
> live monitor via connection-sharing, keystroke/command transcripts) is entirely backend-only.
> This adds the Guacamole Session admin page so an operator can drive it from the console.

## Context

Backend (already shipped, admin-guarded via `requireAdminRole()`; access-service, full prefix
`/api/v1/access`; `internal/access/guacamole_sessions.go`, routes in `internal/access/service.go`):
- `GET  /api/v1/access/guacamole/session-requests` — list **pending** requests → `{requests: GuacSessionRequest[]}`
- `POST /api/v1/access/guacamole/session-requests/:id/approve` → `{request_id,status}`
- `POST /api/v1/access/guacamole/session-requests/:id/deny` → `{request_id,status}`
- `GET  /api/v1/access/guacamole/sessions` — **live** active connections (from Guacamole) → `{sessions: GuacActiveSession[]}`; 503 if Guacamole unconfigured
- `POST /api/v1/access/guacamole/sessions/:id/terminate` — force-terminate by active-conn UUID; body `{reason?}` (optional) → `{message,active_conn_id}`
- `POST /api/v1/access/guacamole/sessions/:id/share` — mint a read-only monitor URL by active-conn UUID → `{share_url}`; **501** `{error}` if the Guacamole server doesn't support sharing profiles
- `GET  /api/v1/access/guacamole/sessions/:id/transcript` — stream the transcript **by `guacamole_sessions` row id**; 404 if none/absent

### DTOs (mirror in TS)
- `GuacSessionRequest`: `id, org_id, connection_id, requester_id, reason?, status, approver_id?, decided_at?, expires_at?, created_at`.
- `GuacActiveSession` (live, from Guacamole): `identifier` (active-conn UUID — used for terminate/share), `connectionIdentifier`, `username`, `remoteHost`, `startDate` (epoch ms).

### The transcript gap → one small backend addition
Transcripts are keyed by the **`guacamole_sessions` row id**, but the only session-listing
endpoint returns *live* Guacamole active-connection identifiers — there is **no endpoint that
lists `guacamole_sessions` DB rows**, so the row id (and thus the transcript) is unreachable from
the UI. Add a minimal, admin-guarded, org-scoped (RLS + explicit `org_id` filter, mirroring
`handleListGuacSessionRequests`) endpoint:
- `GET /api/v1/access/guacamole/sessions/history` → `{sessions: GuacSessionRow[]}` where
  `GuacSessionRow` = `id, connection_id, user_id?, guac_session_uuid?, started_at, ended_at?,
  status, transcript_available (bool = transcript_path <> ''), transcript_generated_at?`
  (from the `guacamole_sessions` table — v59 + v60 columns; **never** returns `recording_path`
  or `transcript_path` themselves, only the availability boolean). Ordered `started_at DESC`,
  `LIMIT 200`.

This mirrors the W1.1 `GET /:id/grants` precedent (a small necessary backend list endpoint,
committed separately with a unit test). No new table, no migration.

## Design

A single admin page `web/admin-console/src/pages/guacamole-sessions.tsx`, following the
`remote-support.tsx` idiom for access-service pages: **raw `api.get/post('/api/v1/access/...')`
calls via the shared axios client** (not a dedicated api section), React Query, `components/ui/*`,
lucide icons. Three tabs:

- **Pending Requests** — table (requester, connection, reason, requested-at, expires) from
  `session-requests`; per-row **Approve** / **Deny** buttons → the approve/deny endpoints;
  invalidate the list on success.
- **Active Sessions** — table (username, remoteHost, connectionIdentifier, started) from
  `sessions`; per-row **Monitor** (calls `share`, opens the returned `share_url` in a new tab;
  on 501 → toast "live monitor not supported by this Guacamole server") and **Terminate**
  (AlertDialog with an optional reason input → `terminate` with `{reason}`). 503 → empty state
  "Guacamole is not configured".
- **Session History** — table (user, connection, started/ended, status badge) from the new
  `sessions/history`; a **Download transcript** button enabled only when `transcript_available`,
  using the shared-axios blob→objectURL→anchor download helper (mirror `remote-support.tsx`'s
  `downloadRecording`), hitting `sessions/:id/transcript`; disabled/greyed when unavailable.

Empty/loading/error states per the existing pages.

## Wiring
- `src/App.tsx` — `<Route path="guacamole-sessions" element={<GuacamoleSessions />} />` + the
  `src/pages/index.ts` barrel export (as the vault pages do) + import.
- `src/components/layout.tsx` — add `{ name: 'Privileged Sessions', href: '/guacamole-sessions',
  icon: MonitorPlay|Monitor, adminOnly: true }` to the existing **"Privileged Access"** group,
  under Rotation Policies.

## Security / UX invariants
- No secret plaintext: sessions carry no credential (M3 injects it server-side); the history DTO
  exposes only a `transcript_available` boolean, never `recording_path`/`transcript_path`.
- Admin-only (route + nav `adminOnly`; backend `requireAdminRole()` enforces every endpoint).
- Force-terminate reason is optional (matches the backend); Monitor share links are read-only.

## Testing
- Backend: extend/keep an existing access test — add a unit-level check that `GuacSessionRow`
  (the history DTO) marshals with **no** `recording_path`/`transcript_path` field (only the
  boolean). If a DB-backed test isn't practical without testcontainers, a struct/JSON-tag
  assertion suffices (mirror `vault/store_test.go:TestDTOsHaveNoValueField`).
- Frontend: colocated `src/pages/guacamole-sessions.test.tsx` (mirror `remote-support.test.tsx`):
  pending list renders + Approve calls the approve endpoint; active list renders + Terminate calls
  terminate + Monitor calls share; history list renders + Download transcript is disabled when
  `transcript_available` is false.
- `cd web/admin-console && npm run type-check && npm run lint && npm test && npm run build` green;
  `go build ./... && go test ./internal/access/ -run Guac` green.

## Out of scope (later slices / backlog)
`vault_credential` in access-requests (W1.4), OpenAPI specs (W1.5), dashboard entry (W1.6).
Streaming/embedded live viewer (we open Guacamole's own share URL in a new tab, as the backend
intends). This slice = the Guacamole Session admin page + the `sessions/history` endpoint +
route/nav + tests.

## Critical files
- New: `web/admin-console/src/pages/guacamole-sessions.tsx`, `.test.tsx`.
- Modify: `internal/access/guacamole_sessions.go` (+ `service.go` route) for the history endpoint;
  `src/App.tsx`, `src/pages/index.ts`, `src/components/layout.tsx`.
- Reuse: `src/pages/remote-support.tsx` (access-service page pattern + blob download helper),
  `components/ui/*`; `internal/access/guacamole_sessions.go` handlers (approve/deny/list/terminate/
  share/transcript already exist).
