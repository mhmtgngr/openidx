# PAM UI — Rotation Policies admin page (readiness W1.2)

> Second slice of the readiness-finalization plan (Workstream 1: make the shipped PAM usable).
> The credential rotation engine (M1b) exposes policy CRUD + on-demand rotate + rotation
> history, all admin-guarded, but has **no admin-console UI**. This adds the Rotation Policies
> management page and surfaces per-secret rotate-now + history on the existing Vault Secrets page.

## Context

Backend (already shipped, admin-guarded — same `RequireAdmin` group as vault, so full prefix is
`/api/v1`; `internal/credentials/handlers.go`):
- `POST   /api/v1/vault/rotation-policies` — create (`PolicyInput`) → `Policy`
- `GET    /api/v1/vault/rotation-policies` — list → `{policies: Policy[]}`
- `GET    /api/v1/vault/rotation-policies/:id` — detail → `Policy`
- `PUT    /api/v1/vault/rotation-policies/:id` — update (`PolicyInput`) → `Policy`
- `DELETE /api/v1/vault/rotation-policies/:id` — delete
- `POST   /api/v1/vault/secrets/:id/rotate` — on-demand rotate → `RotationRun` (or `{status}`); 404 if no policy
- `GET    /api/v1/vault/secrets/:id/rotations` — rotation ledger → `{rotations: RotationRun[]}`

### Backend DTOs (mirror exactly in TS — none carry a secret value)
`Policy`: `id, org_id, secret_id, connector_type, connector_config (obj), generation_policy
(GenerationPolicy), interval_seconds, rotate_on_checkout, enabled, next_run_at?, last_run_at?,
last_status?, created_at, updated_at`.
`PolicyInput` (create/update): `secret_id, connector_type, connector_config (obj),
generation_policy, interval_seconds, rotate_on_checkout, enabled (bool | null on input)`.
`GenerationPolicy`: `length, upper, lower, digits, symbols`.
`RotationRun`: `id, status, trigger, connector_type, version_from?, version_to?,
error_message?, started_at?, completed_at?`.

### Connector-type constraint (important)
`validatePolicyInput` currently accepts only `connector_type ∈ {directory, generate_only}`.
The M5 SSH/Postgres rotators are registered but **not selectable via a policy** (they're
reachable through checkout paths, not scheduled policies). The UI dropdown therefore offers
**Directory** and **Generate-only** only. *Follow-up (out of scope here): a tiny backend change
to let `validatePolicyInput` accept `ssh`/`postgres` so scheduled rotation can use the M5
connectors — filed to the backlog register, not this PR.*
- `directory` connector requires `connector_config.directory_id` and `connector_config.username`.
- `generate_only` needs no extra config.

## Design

A single admin page `web/admin-console/src/pages/rotation-policies.tsx`, mirroring the
just-shipped `vault-secrets.tsx` and `attestation-campaigns.tsx` idioms (React Query
`useQuery`/`useMutation`/`useQueryClient`, the `api` object, `components/ui/*`
Card/Badge/Button/Table/Dialog/AlertDialog/Select/Input/Tabs, lucide icons).

- **List view** — table of policies: target secret (name resolved from the vault list, fall back
  to `secret_id`), connector type badge, interval (human-readable, e.g. `604800s → "7d"`),
  rotate-on-checkout badge, enabled badge, last status + last run, next run. A **Create** button.
- **Create / Edit dialog** — form: secret (a `<Select>` populated from `api.vault.listSecrets()`),
  connector type (`Directory | Generate-only`), directory-only fields (directory_id, username)
  shown when type = directory, interval (a friendly picker: value + unit → seconds; `0` = manual/
  no schedule), rotate-on-checkout toggle, generation policy (length number + upper/lower/digits/
  symbols toggles), enabled toggle. Submit → create or update; invalidate the list.
- **Delete** — AlertDialog confirm.
- **Rotate now + history** — surfaced on the **Vault Secrets detail** page (the natural home,
  since both endpoints are keyed by `secret_id`): add a **Rotate now** button (calls
  `api.vault.rotateNow(secretId)`; on 404 → toast "no rotation policy configured for this
  secret") and a **Rotations** tab (`api.vault.listRotations(secretId)` → `RotationRun[]`:
  status/trigger/connector/version from→to/started/completed/error). This keeps the per-secret
  rotation actions where the operator already is, and the policy list page owns policy CRUD.

- **Empty / loading / error states** per the existing pages; friendly messages (403 → "vault
  admin access required").

### API client (`src/lib/api.ts`)
Extend the existing `api.vault` section:
- `listPolicies()`, `createPolicy(body)`, `getPolicy(id)`, `updatePolicy(id, body)`,
  `deletePolicy(id)`, `rotateNow(secretId)`, `listRotations(secretId)`.
- TS interfaces `VaultRotationPolicy`, `VaultRotationPolicyInput`, `VaultGenerationPolicy`,
  `VaultRotationRun` — mirror the Go DTOs. None carry a value field.

### Wiring
- `src/App.tsx` — add `<Route path="rotation-policies" element={<RotationPolicies />} />` +
  the import.
- `src/components/layout.tsx` — add `{ name: 'Rotation Policies', href: '/rotation-policies',
  icon: RefreshCw|RotateCw, adminOnly: true }` to the existing **"Privileged Access"** group
  (created in W1.1), directly under Vault Secrets.

## Security / UX invariants
- No secret plaintext anywhere on this page — policies and rotation runs carry only metadata
  (the DTOs have no value field; a `RotationRun` reports version numbers, never values).
- Admin-only (route + nav `adminOnly`; backend `RequireAdmin` enforces).

## Testing
- Colocated `src/pages/rotation-policies.test.tsx` (mirror `vault-secrets.test.tsx`, mock
  `api.vault.*`): list renders from a mocked `listPolicies`; create calls `createPolicy` +
  invalidates; the connector dropdown offers exactly Directory + Generate-only; directory fields
  appear only when type = directory.
- For the Vault Secrets additions, extend `vault-secrets.test.tsx`: Rotate-now button calls
  `rotateNow`; a Rotations tab renders `listRotations` results.
- `cd web/admin-console && npm run type-check && npm run lint && npm test && npm run build` green.

## Out of scope (later W1 slices / backlog)
Guacamole Session admin (W1.3), `vault_credential` in access-requests (W1.4), OpenAPI specs
(W1.5). Backend change to allow `ssh`/`postgres` policy connector types → backlog. This slice is
the Rotation Policies page + per-secret rotate-now/history + api methods + route/nav + tests.

## Critical files
- New: `web/admin-console/src/pages/rotation-policies.tsx`, `src/pages/rotation-policies.test.tsx`.
- Modify: `src/lib/api.ts` (rotation methods + interfaces), `src/App.tsx` (route),
  `src/components/layout.tsx` (nav), `src/pages/vault-secrets.tsx` (rotate-now + Rotations tab) +
  its test.
- Reuse: `src/pages/vault-secrets.tsx` / `attestation-campaigns.tsx` (page pattern),
  `components/ui/*`. Backend unchanged (`internal/credentials/handlers.go`).
