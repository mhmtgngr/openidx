# Guacamole recording legal-hold — admin console UI

**Goal:** Give operators a UI to place/release recording legal-holds on Guacamole sessions, wired
to the v1.15.0 backend endpoints. Today those endpoints (`POST/DELETE .../legal-hold`,
`GET .../legal-holds`) exist and are admin-gated + org-scoped, but the only way to drive them is
`curl` — the admin console has no controls.

**Verified current state (2026-07-06):**
- **Backend endpoints exist** (`internal/access/guacamole_legal_hold.go`, v1.15.0), registered in
  `service.go` under `svc.requireAdminRole()`, keyed on `guacamole_sessions.id`:
  - `POST   /api/v1/access/guacamole/sessions/:id/legal-hold` — insert a hold (reason required); **409** if an active hold already exists.
  - `DELETE /api/v1/access/guacamole/sessions/:id/legal-hold` — release the active hold (reason optional).
  - `GET    /api/v1/access/guacamole/sessions/:id/legal-holds` — list active + historical holds.
- **Reference UI pattern:** `web/admin-console/src/pages/remote-support.tsx` already does exactly this
  for remote-support sessions — a per-row `is_on_legal_hold` flag drives a "Place hold"/"Release"
  button, `window.prompt` collects the reason, `api.post` / `api.delete(url, { data: { reason } })`
  mutations, toast + `invalidateQueries`.
- **Target page:** `web/admin-console/src/pages/guacamole-sessions.tsx` has a **Session History**
  table (queryKey `['guac-session-history']`, `GET /api/v1/access/guacamole/session-history`) whose
  row type `GuacSessionRow` has `id` (= `guacamole_sessions.id`), `connection_id`, `status`,
  `transcript_available`, etc. — but **no legal-hold flag and no recording flag**.
- **The gap:** to render place-vs-release cleanly (mirroring `is_on_legal_hold`), the history rows
  need an `on_legal_hold` boolean. They also should only offer a legal-hold on sessions that actually
  have a recording, so a `recording_available` boolean is useful too. The history query
  (`handleListGuacSessionHistory` in `guacamole_sessions.go` ~line 229) currently returns neither.
- Tests: `vitest` (`npm test`); `api.delete` supports a request-body config (`{ data: { reason } }`).

## Design

### 1. Backend — add two flags to the session-history response (small)
Extend `handleListGuacSessionHistory`'s SELECT (and its row scan + JSON shape) with two computed
columns (the query uses **no table alias** — `FROM guacamole_sessions` — so references are
unqualified / `guacamole_sessions.id`):
```sql
       (COALESCE(recording_path, '') <> '')                          AS recording_available,
       EXISTS (SELECT 1 FROM guacamole_recording_legal_holds h
                WHERE h.session_id = guacamole_sessions.id AND h.released_at IS NULL) AS on_legal_hold
```
(kept inside the existing org-scoped `WHERE org_id = $1`, so the flags are computed only for the
caller's own sessions). Add matching `RecordingAvailable`/`OnLegalHold bool` fields to `GuacSessionRow`
(`recording_available` / `on_legal_hold` JSON tags), scan them, and they ride along in the existing
`gin.H{"sessions": sessions}` response. No new table, no migration — `guacamole_recording_legal_holds`
already exists (v68).

### 2. Frontend — legal-hold controls on the Session History table
In `guacamole-sessions.tsx`, mirroring `remote-support.tsx`:
- Add `recording_available: boolean` and `on_legal_hold: boolean` to `GuacSessionRow`.
- Add two mutations:
  - `placeHoldMutation`: `(id) => api.post(\`/api/v1/access/guacamole/sessions/${id}/legal-hold\`, { reason })`
  - `releaseHoldMutation`: `(id) => api.delete(\`/api/v1/access/guacamole/sessions/${id}/legal-hold\`, { data: { reason } })`
  - both: on success `invalidateQueries(['guac-session-history'])` + toast; on error a destructive toast
    (the place mutation surfaces the 409 "already on hold" as a toast).
- In the history table's actions cell, for rows where `recording_available` is true, render a
  legal-hold button:
  - if `row.on_legal_hold` → **"Release hold"** → `window.prompt('Reason for releasing the legal hold (optional):')` (null → cancel) → `releaseHoldMutation`.
  - else → **"Place hold"** → `window.prompt('Reason for the legal hold (e.g. "litigation case #1234"):')` → `if (!reason) return` → `placeHoldMutation`.
  Held rows get a small "On hold" badge/label (mirror remote-support) so the state is visible at a glance.
- Rows with no recording show no legal-hold control (a hold only protects a recording).

### 3. Tests (`vitest`, colocated)
A `guacamole-sessions.test.tsx` (or extend an existing one) that mounts the page with a mocked
`api` and a mocked history response containing one recorded row `on_legal_hold: false` and one
`on_legal_hold: true`, then asserts:
- the un-held recorded row shows "Place hold"; clicking it (with `window.prompt` stubbed to a reason)
  calls `api.post` with the `/legal-hold` URL and `{ reason }`.
- the held row shows "Release hold" + the "On hold" indicator; clicking it calls `api.delete` with
  the `/legal-hold` URL and `{ data: { reason } }`.
- a row with `recording_available: false` shows no legal-hold button.

## Testing / verification
- Frontend: `cd web/admin-console && npm test` (new test green) + `npm run build` (tsc + vite clean).
- Backend: `go build ./... && go vet ./... && gofmt -l` clean; `go run ./tools/orgscope -fail ./internal/access`
  (the new subquery stays inside the org-scoped query — no new `//orgscope:ignore`).
- The existing guac legal-hold endpoint tests (v1.15.0) already cover place/release/409/list; this PR
  adds the history-flag read path — an optional backend assertion that the history query returns
  `on_legal_hold: true` when an active hold exists can piggy-back on the existing testcontainer helper.
- Optional box smoke after release: log in as admin → Guacamole Sessions → on a recorded history row,
  Place hold (reason) → row shows "On hold" → Release hold → indicator clears (throwaway hold cleaned up).

## Scope / risk
- **Single PR**, low risk: one small backend query addition (two computed read-only flags, org-scoped)
  + frontend controls on an existing table + a vitest. No migration, no new endpoint, no schema change.
- Files: `internal/access/guacamole_sessions.go` (history query + response), `web/admin-console/src/pages/guacamole-sessions.tsx` (+ its test).
- Out of scope: a dedicated "legal holds" list view / the `GET .../legal-holds` history drawer (the
  per-row place/release + "On hold" badge is the whole MVP, matching remote-support); bulk hold actions;
  holds on live/active sessions that have not yet produced a recording.

## Resolved at investigation
1. The history query uses no table alias (`FROM guacamole_sessions`); recording path column is
   `recording_path`. Subquery references `guacamole_sessions.id`, unqualified `recording_path`.
2. `SessionHistoryTab` already has an actions cell (the Transcript `<Button>`, ~line 503) — the
   legal-hold button goes in that same cell (wrap the two buttons in a `flex gap-2` div). The tab is
   its own component with only `useToast` in scope → add `useQueryClient` for the mutations to invalidate.
