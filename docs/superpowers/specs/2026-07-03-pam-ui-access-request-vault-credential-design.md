# PAM UI — JIT vault_credential checkout in access-requests (readiness W1.4)

> Fourth slice of the readiness-finalization plan (Workstream 1). The highest-value PAM user
> journey — request → approve → **retrieve a time-boxed credential once** → **return early** —
> is fully implemented backend-side (M2b) but unreachable from the console: the access-requests
> page's resource-type dropdown is hardcoded to role/group/application and there are no
> retrieve/return actions. This slice wires that journey into the existing page.

## Context

Backend (already shipped; governance-service; full prefix `/api/v1/governance`;
`internal/governance/workflows.go`, routes in `service.go`):
- `POST /api/v1/governance/requests` — create. For `resource_type = "vault_credential"` the body
  **must** carry `resource_id` = an existing **`vault_secrets` UUID** (validated, org-scoped by
  RLS → 400 "vault secret not found or not accessible" otherwise) **and** a non-empty `duration`
  (400 "vault_credential requests require a duration"). `resource_name` is the human label.
- `POST /api/v1/governance/requests/:id/approve` — existing; for vault_credential, approval's
  `fulfillRequest` grants a time-boxed vault reveal grant and sets `status = "fulfilled"`.
- `POST /api/v1/governance/requests/:id/credential` — **retrieve** (requester-only, status must be
  `fulfilled`, within the window) → `{value}` **once**; 409 if not fulfilled, 403 if expired /
  not-your-request, 503 if vault unconfigured.
- `POST /api/v1/governance/requests/:id/return` — **return early** (requester-only, status
  `fulfilled`) → `{status:"returned"}`; revokes the grant immediately, marks the request expired,
  triggers rotate-on-return. 409 if not currently checked out.

The page already lists requests (`GET /requests?requester_id=me`, `/my-approvals`, `/requests`),
creates them, and has cancel/approve/deny. It uses the shared `api.get/post` client and (from
W1.1) `api.vault.listSecrets()`.

## Design (edit `web/admin-console/src/pages/access-requests.tsx` only + its test)

**1. Create dialog — add the `vault_credential` type + secret picker + required duration.**
- Add `<SelectItem value="vault_credential">Vault Credential</SelectItem>` to the resource-type
  dropdown.
- Add a `secretId` field to the `newReq` state. When `resource_type === 'vault_credential'`:
  - Replace the free-text **Resource Name** input with a **secret `<Select>`** populated from
    `api.vault.listSecrets()` (query key `['vault-secrets']`, enabled only when the vault type is
    selected). On select, set `secretId = secret.id` and `resource_name = secret.name` (the label).
  - **Duration is required**: drop the "Permanent" (`''`) option from the picker for this type, and
    disable Submit until a duration is chosen. Keep the existing behavior for other types.
- Create payload: when vault_credential, POST `{resource_type, resource_id: secretId,
  resource_name, justification, priority, duration}` (do **not** apply the `duration==='permanent'
  → ''` transform for this type; it can't be permanent). For non-vault types keep the current
  payload exactly (no `resource_id`; permanent→'' transform preserved).
- Submit disabled logic for vault_credential: require `secretId` **and** a non-empty `duration`.

**2. My Requests table — retrieve / return actions for fulfilled vault_credential rows.**
For a row where `resource_type === 'vault_credential' && status === 'fulfilled'`, in the Actions
cell add:
- **Retrieve** button → `api.post('/api/v1/governance/requests/${id}/credential')` → open a modal
  showing the returned `value` **once** (read-only, copy-to-clipboard, "shown once — not stored"
  note; value cleared from state when the modal closes). Mirror the vault-secrets reveal modal.
  On 409/403 show a toast with the backend error (e.g. "checkout window expired").
- **Return early** button → AlertDialog confirm → `api.post('.../requests/${id}/return')` →
  invalidate the requests queries; toast "Credential returned".
Keep the existing `pending → Cancel` action. (Rows can show Cancel when pending, Retrieve/Return
when fulfilled.)

**3. Types.** Add `resource_id?: string` to the `AccessRequest` interface (the backend returns it;
needed only incidentally). No value field is stored on any request DTO — the plaintext exists only
in the transient retrieve-modal state.

## Security / UX invariants
- The retrieved plaintext appears **only** in the retrieve modal, shown once, cleared on close;
  never rendered in the table, never persisted. (Same invariant as the vault-secrets reveal.)
- Retrieve/Return are requester-only (backend enforces; the buttons live in **My Requests**).
- vault_credential is always time-boxed (duration required) — no permanent privileged checkout.

## Testing (`access-requests.test.tsx`)
Extend the existing test (mirror its setup; mock `api.get/post` and `api.vault.listSecrets`):
- Selecting `Vault Credential` shows the secret picker and requires a duration (Submit disabled
  until both secret + duration are set; the create POST carries `resource_id`).
- A fulfilled vault_credential row in My Requests shows Retrieve + Return; Retrieve posts to
  `/credential` and displays the returned value; Return posts to `/return`.
- A non-vault row is unaffected (still free-text name, permanent allowed).
- `cd web/admin-console && npm run type-check && npm run lint && npm test -- --run access-requests && npm run build` green.

## Out of scope (later slices)
OpenAPI specs (W1.5), dashboard/nav wrap-up (W1.6). Backend is unchanged — all endpoints exist.

## Critical files
- Modify: `web/admin-console/src/pages/access-requests.tsx` (+ `access-requests.test.tsx`).
- Reuse: `api.vault.listSecrets()` (W1.1), the shared `api.get/post`, the vault-secrets reveal-modal
  pattern, existing ui components already imported in the page. Backend unchanged
  (`internal/governance/workflows.go`).
