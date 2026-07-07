# Rotation-policies UI — SSH / SSH-key / PostgreSQL / MySQL connectors

**Goal:** The rotation-policies admin page can only create `directory` and `generate_only` policies —
its **Connector Type** dropdown offers just those two. But the backend registers six rotators
(`directory`, `generate_only`, `ssh`, `ssh_key`, `postgres`, `mysql`) and, since v1.14.1 (#316),
`CreatePolicy` accepts any registered type + validates its config via the `ConfigValidator` interface.
So the SSH/DB rotation connectors shipped in v1.14.0 are **usable only via `curl`**. Add them to the
UI with the per-connector config fields each one requires.

**Verified current state (2026-07-07):**
- Page: `web/admin-console/src/pages/rotation-policies.tsx`. The Connector Type `Select` (~line 452)
  has only `directory` + `generate_only`. `formToInput` (~line 146) builds `connector_config` only for
  `directory` (`{ directory_id, username }`), else `{}`. `isFormValid` (~line 252) only special-cases
  `directory`. A `directory`-only config block renders when `connectorType === 'directory'` (~line 459).
- The page already loads the vault secrets list (`secrets: VaultSecretMeta[]`, query key
  `['vault-secrets']`, ~line 182) for the target-secret `Select` — reuse it for the `admin_secret_id`
  picker each DB/SSH connector needs.
- Backend needs **no change**: `CreatePolicy` validates via each rotator's `ValidateConfig`
  (`internal/credentials/*_rotator.go`). `connector_config` is a free-form JSON map on the
  rotation-policy endpoint — no OpenAPI/schema change.

### Exact config each connector requires (from `*ConfigFromMap` in `internal/credentials/`)

| Connector | Required keys | Optional keys (backend default) |
|-----------|---------------|----------------------------------|
| `ssh` (password) | `host`, `username`, `admin_secret_id`, `admin_username`, `host_key` | `port` (22), `admin_auth` (`password`) |
| `ssh_key` (key-pair) | same as `ssh` (shared `sshConfigFromMap`) | `port` (22), `admin_auth` (`password`) |
| `postgres` | `host`, `dbname`, `admin_secret_id`, `admin_username`, `target_role` | `port` (5432), `sslmode` (`require`) |
| `mysql` | `host`, `admin_secret_id`, `admin_username`, `target_user` | `port` (3306), `target_host` (`%`), `dbname`, `tls` (bool) |

Notes: `admin_secret_id` is a **vault secret ID** holding the admin credential used to perform the
rotation (distinct from the policy's target secret) → rendered as a secret-picker. `host_key` is the
pinned SSH server host key → a `textarea`. MySQL `target_user`/`target_host` are validated backend-side
against `mysqlIdentRE`; the UI just collects them (backend returns a clear 400 on a bad value).

## Design

### 1. Declarative connector-field schema (single source of truth)
Add a small table that drives both rendering and validation — avoids bloating `PolicyFormState` with
~12 discrete fields and keeps the four connectors DRY:

```ts
type ConnectorFieldType = 'text' | 'number' | 'secret' | 'textarea' | 'select' | 'checkbox'
interface ConnectorField {
  key: string            // connector_config key
  label: string
  required: boolean
  type: ConnectorFieldType
  placeholder?: string
  options?: { value: string; label: string }[] // for 'select'
  default?: string       // prefilled into the config bag when the connector is chosen
}
const CONNECTOR_FIELDS: Record<string, ConnectorField[]> = {
  ssh:      [...],  // host, port(22), username, admin_secret_id(secret), admin_username,
                    //   admin_auth(select password|key, default password), host_key(textarea)
  ssh_key:  [...],  // identical field set to ssh
  postgres: [...],  // host, port(5432), dbname, sslmode(select require|disable|verify-ca|verify-full),
                    //   admin_secret_id(secret), admin_username, target_role
  mysql:    [...],  // host, port(3306), dbname(optional), tls(checkbox), admin_secret_id(secret),
                    //   admin_username, target_user, target_host(default %)
}
```

### 2. Form state: a generic config bag
Add `connectorConfig: Record<string, string>` to `PolicyFormState` (keep the existing discrete
`directoryId`/`username` for the unchanged `directory` branch). On connector-type change, reset the bag
and seed any `default` values from `CONNECTOR_FIELDS`. `checkbox` (mysql `tls`) stored as `'true'`/`''`.

### 3. Render + wire
- Extend the Connector Type `Select` with four `SelectItem`s (`ssh`, `ssh_key`, `postgres`, `mysql`)
  and `connectorLabels`/`connectorColors` entries so existing policies of these types render with a
  proper label/badge.
- When the selected type is one of the four, render its `CONNECTOR_FIELDS` (map over the schema):
  `secret` → a `Select` over `secrets`; `select` → a `Select` over `options`; `textarea` → a textarea;
  `checkbox` → a checkbox; `number`/`text` → an `Input`. Bind to `form.connectorConfig[field.key]`.
- `formToInput`: for these types, assemble `connector_config` from the bag — include non-empty values,
  coerce `port` to a number when numeric, coerce `tls` to a boolean. (Directory/generate_only unchanged.)
- `policyToForm`: load `p.connector_config` into `connectorConfig` (stringify booleans/numbers) so Edit
  round-trips.
- `isFormValid`: for these types, require every `required` field in the schema to be non-empty (drop the
  directory-only special-case into the same schema-driven check).

## Testing / verification
- **Vitest** (`web/admin-console/src/pages/rotation-policies.test.tsx`): 
  - Selecting `MySQL` reveals its required fields; filling host/admin_secret_id/admin_username/target_user
    (+ picking a secret) and submitting calls the create mutation with
    `connector_type: 'mysql'` and a `connector_config` containing those keys (port coerced to number).
  - Selecting `SSH key-pair` reveals `host_key` (textarea) + the admin-secret picker; submit builds
    `connector_type: 'ssh_key'` config.
  - Submit stays disabled until a connector's required fields are filled (e.g. `postgres` missing
    `target_role`).
- `cd web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx` green; `npm run build`
  clean (tsc + vite).
- No backend/Go change → no Go gates needed beyond confirming nothing else was touched.

## Scope / risk
- **Single PR, frontend-only**, low risk. One file + its test: `rotation-policies.tsx` (+ `.test.tsx`).
  Backend validation already exists; a bad config yields a clear 400 surfaced via the existing error
  toast.
- Out of scope: cloud-IAM connectors (separate backlog item); a secret *creation* shortcut from this
  page (admin secret must already exist in the vault); rotate-now/history changes (unchanged).

## Resolved at investigation
1. Config keys/required-ness taken verbatim from `sshConfigFromMap` / `pgConfigFromMap` /
   `mysqlConfigFromMap` (see table above) — the form's required-field set matches the backend validators.
2. Secrets list for the `admin_secret_id` picker = the existing `['vault-secrets']` query already on the page.
3. `directory` + `generate_only` branches are left exactly as they are; the new schema-driven path is
   additive.
