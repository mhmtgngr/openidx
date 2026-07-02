# PAM UI — Vault Secrets admin page (readiness W1.1)

> First slice of the readiness-finalization plan (Workstream 1: make the shipped PAM usable).
> The credential vault (M1) has 9 admin-guarded endpoints but **no admin-console UI** — an
> operator can only manage secrets via `curl`. This adds the Vault Secrets management page.

## Context

Backend (already shipped, admin-guarded under `RequireAdmin`, base path **`/api/v1/vault/secrets`**
— `internal/vault/handlers.go`):
- `POST   /api/v1/vault/secrets` — create (`{name,type,description,value,metadata}`) → metadata (no value)
- `GET    /api/v1/vault/secrets` — list (metadata only)
- `GET    /api/v1/vault/secrets/:id` — detail (metadata + version history, **no value**)
- `PUT    /api/v1/vault/secrets/:id/version` — new version (`{value}`)
- `DELETE /api/v1/vault/secrets/:id` — delete (crypto-erase)
- `POST   /api/v1/vault/secrets/:id/reveal` — `{reason}` → returns the plaintext **once**, audited
- `POST   /api/v1/vault/secrets/:id/grants` — add grant (`{principal_type,principal_id,actions,expires_at}`)
- `DELETE /api/v1/vault/secrets/:id/grants/:grantId` — remove grant
- `GET    /api/v1/vault/secrets/:id/checkouts` — checkout/reveal audit ledger

## Design

A single admin page `web/admin-console/src/pages/vault-secrets.tsx`, mirroring the structure/idioms
of `src/pages/attestation-campaigns.tsx` + `access-requests.tsx` (React Query `useQuery`/`useMutation`,
the `api` object from `../lib/api`, `components/ui/*` Card/Badge/Button/LoadingSpinner/Dialog, lucide
icons). Route + nav below.

- **List view** — table of secrets (name, type badge, current version, updated_at) with a **Create**
  button. **No secret value is ever shown in the list or detail** — enforced by the DTOs (they carry no
  value) and by UI never requesting one outside reveal.
- **Create dialog** — form: name, type (`password|api_key|ssh_key|generic`), description, value
  (password input), optional metadata. On success, invalidate the list query; never echo the value back.
- **Detail drawer/panel** (select a row) — three sections:
  - *Versions*: current_version + version history (from `GET /:id`), a **New version** action (value input).
  - *Grants*: list `vault_access_grants` for the secret (principal, actions, expiry); **Add grant**
    (principal_type/id, actions `use`/`reveal`, optional expiry) + **Remove**.
  - *Checkouts*: the audit ledger (`GET /:id/checkouts`) — mode/reason/principal/leased_at/status.
  - **Reveal** action → a modal that **requires a reason**, calls reveal, shows the returned value once in
    a copy-to-clipboard field with a "value shown once; not stored" note, and clears it on close. Guard so
    the value is never persisted to component state longer than needed / never logged.
  - **Delete** with a confirm ("crypto-erase — unrecoverable").
- **Empty/loading/error states** per the existing pages' pattern; friendly messages (e.g., 403 → "vault
  admin access required", 503 → "vault not configured").

### API client (`src/lib/api.ts`)
Add a `vault` section to the `api` object (mirroring existing sections): `listSecrets`, `createSecret`,
`getSecret`, `newVersion`, `deleteSecret`, `reveal(id, reason)`, `listGrants` (via getSecret or a
dedicated call — grants come back on detail or a separate fetch; use what the handler returns),
`addGrant`, `removeGrant(id, grantId)`, `listCheckouts(id)`. Add TS interfaces `VaultSecretMeta`,
`VaultSecretDetail`, `VaultVersion`, `VaultGrant`, `VaultCheckout` (mirror the Go DTOs — **none carry a
value field**).

### Wiring
- `src/App.tsx` — add `<Route path="vault-secrets" element={<VaultSecrets />} />` inside the authed
  layout (mirror the other admin routes ~line 172+), with the import.
- `src/components/layout.tsx` — add a **"Privileged Access"** admin nav group (or an item under an existing
  admin section) `{ name: 'Vault Secrets', href: '/vault-secrets', icon: KeyRound|Lock, adminOnly: true }`.
  (Rotation Policies / Guacamole Sessions items land here in later slices.)

## Security / UX invariants
- The plaintext appears **only** through the reason-gated reveal modal, shown once, never in the list,
  detail, logs, or persisted state; the create/new-version value inputs are write-only (never re-read).
- Page is admin-only (route + nav `adminOnly`, backend `RequireAdmin` already enforces).

## Testing
- Colocated `src/pages/vault-secrets.test.tsx` (mirror `attestation-campaigns.test.tsx`): renders the list
  from a mocked `api.vault.listSecrets`; create calls `createSecret` + invalidates; reveal requires a
  reason and displays the returned value; asserts **no value field is rendered in the list/detail**.
- `cd web/admin-console && npm run build` (tsc) + `npm run lint` + `npm test` green.

## Out of scope (later W1 slices)
Rotation Policies page (W1.2), Guacamole Session admin (W1.3), `vault_credential` in access-requests
(W1.4), OpenAPI specs (W1.5). This slice is the Vault Secrets page + its api methods + route/nav + test.

## Critical files
- New: `web/admin-console/src/pages/vault-secrets.tsx`, `src/pages/vault-secrets.test.tsx`.
- Modify: `web/admin-console/src/lib/api.ts` (vault methods + interfaces), `src/App.tsx` (route),
  `src/components/layout.tsx` (nav).
- Reuse: `src/pages/attestation-campaigns.tsx` / `access-requests.tsx` (page pattern), `components/ui/*`,
  the `api` axios client. Backend unchanged (`internal/vault/handlers.go`).
