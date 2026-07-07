# Rotation-policies connector UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators create `ssh` / `ssh_key` / `postgres` / `mysql` rotation policies from the admin console, with each connector's required config fields, wired to the existing backend (no backend change).

**Architecture:** A declarative `CONNECTOR_FIELDS` schema (one table: per-connector field list with key/label/required/type) drives both the dynamic form rendering and client-side validation. Form state gains a generic `connectorConfig: Record<string,string>` bag; `formToInput`/`policyToForm`/`isFormValid` gain a schema-driven branch. The `directory` and `generate_only` branches are untouched.

**Tech Stack:** React 18 + TypeScript, @tanstack/react-query, Radix UI Select, Vitest + Testing Library. All changes in `web/admin-console/src/pages/rotation-policies.tsx` + its test.

---

### Task 1: Connector schema, config-bag state, expanded dropdown

**Files:**
- Modify: `web/admin-console/src/pages/rotation-policies.tsx` (label/color maps ~line 53-61; `PolicyFormState` ~line 92-106; `blankForm` ~line 108; connector-type `Select` ~line 444-455)
- Test: `web/admin-console/src/pages/rotation-policies.test.tsx` (update the existing dropdown test ~line 110-130)

- [ ] **Step 1: Update the failing dropdown test to expect all six connector types**

The existing test asserts the dropdown offers *exactly* Directory + Generate-only. Replace it (lines ~110-130) with:

```tsx
  it('connector dropdown offers all six connector types', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('connector-select'))

    const labels = screen.getAllByRole('option').map((o) => o.textContent)
    expect(labels).toEqual(
      expect.arrayContaining([
        'Directory',
        'Generate-only',
        'SSH (password)',
        'SSH key-pair',
        'PostgreSQL',
        'MySQL',
      ]),
    )
  })
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx -t "all six connector types"`
Expected: FAIL — only Directory + Generate-only options exist.

- [ ] **Step 3: Add the connector-field schema + helpers (top of the module)**

In `rotation-policies.tsx`, immediately after the `connectorColors` map (~line 61), add:

```tsx
// ── Connector config schema ──────────────────────────────────────────────────
// One declarative table drives both the dynamic form fields and validation.
// Keys/required-ness mirror the backend validators (sshConfigFromMap /
// pgConfigFromMap / mysqlConfigFromMap in internal/credentials/).
type ConnectorFieldType = 'text' | 'number' | 'secret' | 'textarea' | 'select' | 'checkbox'
interface ConnectorField {
  key: string
  label: string
  required: boolean
  type: ConnectorFieldType
  placeholder?: string
  options?: { value: string; label: string }[]
  default?: string
}

// ssh and ssh_key share the exact same config (sshConfigFromMap).
const SSH_FIELDS: ConnectorField[] = [
  { key: 'host', label: 'Host', required: true, type: 'text', placeholder: 'ssh.example.com' },
  { key: 'port', label: 'Port', required: false, type: 'number', placeholder: '22', default: '22' },
  { key: 'username', label: 'Target username', required: true, type: 'text', placeholder: 'svc-account' },
  { key: 'admin_secret_id', label: 'Admin secret', required: true, type: 'secret' },
  { key: 'admin_username', label: 'Admin username', required: true, type: 'text', placeholder: 'root' },
  {
    key: 'admin_auth', label: 'Admin auth method', required: false, type: 'select', default: 'password',
    options: [{ value: 'password', label: 'Password' }, { value: 'key', label: 'Key' }],
  },
  { key: 'host_key', label: 'Host key (pinned)', required: true, type: 'textarea', placeholder: 'ssh-ed25519 AAAA...' },
]

const CONNECTOR_FIELDS: Record<string, ConnectorField[]> = {
  ssh: SSH_FIELDS,
  ssh_key: SSH_FIELDS,
  postgres: [
    { key: 'host', label: 'Host', required: true, type: 'text', placeholder: 'db.example.com' },
    { key: 'port', label: 'Port', required: false, type: 'number', placeholder: '5432', default: '5432' },
    { key: 'dbname', label: 'Database', required: true, type: 'text', placeholder: 'appdb' },
    {
      key: 'sslmode', label: 'SSL mode', required: false, type: 'select', default: 'require',
      options: ['disable', 'require', 'verify-ca', 'verify-full'].map((v) => ({ value: v, label: v })),
    },
    { key: 'admin_secret_id', label: 'Admin secret', required: true, type: 'secret' },
    { key: 'admin_username', label: 'Admin username', required: true, type: 'text', placeholder: 'postgres' },
    { key: 'target_role', label: 'Target role', required: true, type: 'text', placeholder: 'app_role' },
  ],
  mysql: [
    { key: 'host', label: 'Host', required: true, type: 'text', placeholder: 'db.example.com' },
    { key: 'port', label: 'Port', required: false, type: 'number', placeholder: '3306', default: '3306' },
    { key: 'dbname', label: 'Database (optional)', required: false, type: 'text', placeholder: 'appdb' },
    { key: 'tls', label: 'Use TLS', required: false, type: 'checkbox' },
    { key: 'admin_secret_id', label: 'Admin secret', required: true, type: 'secret' },
    { key: 'admin_username', label: 'Admin username', required: true, type: 'text', placeholder: 'root' },
    { key: 'target_user', label: 'Target user', required: true, type: 'text', placeholder: 'app_user' },
    { key: 'target_host', label: 'Target host', required: false, type: 'text', placeholder: '%', default: '%' },
  ],
}

// Connector types whose config is driven by CONNECTOR_FIELDS (vs the bespoke
// directory branch and the config-less generate_only).
const SCHEMA_CONNECTORS = ['ssh', 'ssh_key', 'postgres', 'mysql']

// Seed a config bag with the schema's default values when a connector is chosen.
function seedConnectorConfig(type: string): Record<string, string> {
  const fields = CONNECTOR_FIELDS[type]
  if (!fields) return {}
  const bag: Record<string, string> = {}
  for (const f of fields) if (f.default !== undefined) bag[f.key] = f.default
  return bag
}
```

- [ ] **Step 4: Extend the label + color maps**

Replace the `connectorLabels` and `connectorColors` maps (~line 53-61) with:

```tsx
const connectorLabels: Record<string, string> = {
  directory: 'Directory',
  generate_only: 'Generate-only',
  ssh: 'SSH (password)',
  ssh_key: 'SSH key-pair',
  postgres: 'PostgreSQL',
  mysql: 'MySQL',
}

const connectorColors: Record<string, string> = {
  directory: 'bg-blue-100 text-blue-800',
  generate_only: 'bg-green-100 text-green-800',
  ssh: 'bg-purple-100 text-purple-800',
  ssh_key: 'bg-purple-100 text-purple-800',
  postgres: 'bg-sky-100 text-sky-800',
  mysql: 'bg-orange-100 text-orange-800',
}
```

- [ ] **Step 5: Add the config bag to form state**

Add `connectorConfig: Record<string, string>` to `PolicyFormState` (after `username`, ~line 96):

```tsx
interface PolicyFormState {
  secretId: string
  connectorType: string
  directoryId: string
  username: string
  connectorConfig: Record<string, string>
  intervalValue: number
  intervalUnit: IntervalUnit
  rotateOnCheckout: boolean
  genLength: number
  genUpper: boolean
  genLower: boolean
  genDigits: boolean
  genSymbols: boolean
  enabled: boolean
}
```

And initialise it in `blankForm()` (after `username: ''`, ~line 113):

```tsx
    username: '',
    connectorConfig: {},
```

- [ ] **Step 6: Expand the connector-type dropdown + seed the bag on change**

Replace the connector-type `Select` (~line 444-455) with:

```tsx
              <Select
                value={form.connectorType}
                onValueChange={(v) =>
                  setForm((f) => ({ ...f, connectorType: v, connectorConfig: seedConnectorConfig(v) }))
                }
              >
                <SelectTrigger className="mt-1" data-testid="connector-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="directory">Directory</SelectItem>
                  <SelectItem value="generate_only">Generate-only</SelectItem>
                  <SelectItem value="ssh">SSH (password)</SelectItem>
                  <SelectItem value="ssh_key">SSH key-pair</SelectItem>
                  <SelectItem value="postgres">PostgreSQL</SelectItem>
                  <SelectItem value="mysql">MySQL</SelectItem>
                </SelectContent>
              </Select>
```

- [ ] **Step 7: Run the dropdown test to verify it passes**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx -t "all six connector types"`
Expected: PASS.

- [ ] **Step 8: Type-check the file compiles (bag unused elsewhere yet is fine)**

Run: `cd /home/cmit/openidx/web/admin-console && npx tsc -b`
Expected: no errors. (`seedConnectorConfig`, `CONNECTOR_FIELDS`, `SCHEMA_CONNECTORS` are referenced; `ConnectorField` type used. If tsc flags an unused symbol, it will be consumed in Task 2 — but all are already referenced by Step 6/3, so it should be clean.)

- [ ] **Step 9: Commit**

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/rotation-policies.tsx web/admin-console/src/pages/rotation-policies.test.tsx
git commit -m "feat(admin-console): rotation-policies connector schema + expanded dropdown

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Dynamic connector fields, config assembly, validation, round-trip

**Files:**
- Modify: `web/admin-console/src/pages/rotation-policies.tsx` (`policyToForm` ~line 126; `formToInput` ~line 146; `isFormValid` ~line 252; directory render block ~line 458-482)
- Test: `web/admin-console/src/pages/rotation-policies.test.tsx`

- [ ] **Step 1: Write failing tests for the dynamic fields + config assembly**

Add these tests to `rotation-policies.test.tsx` inside the top-level `describe` block (after the existing `calls createPolicy...` test, ~line 180). They render fields by `data-testid={`cc-<key>`}`:

```tsx
  it('MySQL connector reveals its fields and builds connector_config on submit', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    // target secret
    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    // connector = MySQL
    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'MySQL' }))

    // required fields appear
    expect(screen.getByTestId('cc-host')).toBeInTheDocument()
    expect(screen.getByTestId('cc-target_user')).toBeInTheDocument()

    await user.type(screen.getByTestId('cc-host'), 'db.example.com')
    await user.type(screen.getByTestId('cc-admin_username'), 'root')
    await user.type(screen.getByTestId('cc-target_user'), 'app_user')
    // admin secret picker (reuses the vault secrets list)
    await user.click(screen.getByTestId('cc-admin_secret_id'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    await waitFor(() => {
      expect(vi.mocked(api.vault.createPolicy)).toHaveBeenCalledWith(
        expect.objectContaining({
          secret_id: 'sec-1',
          connector_type: 'mysql',
          connector_config: expect.objectContaining({
            host: 'db.example.com',
            admin_username: 'root',
            admin_secret_id: 'sec-1',
            target_user: 'app_user',
            target_host: '%',
            port: 3306,
          }),
        }),
      )
    })
  })

  it('SSH key-pair connector reveals the host-key textarea and admin-secret picker', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'SSH key-pair' }))

    expect(screen.getByTestId('cc-host_key')).toBeInTheDocument()
    expect(screen.getByTestId('cc-admin_secret_id')).toBeInTheDocument()
    expect(screen.getByTestId('cc-username')).toBeInTheDocument()
  })

  it('submit stays disabled until a connector’s required fields are filled', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'PostgreSQL' }))

    // target_role not filled yet -> submit disabled
    expect(screen.getByRole('button', { name: /create policy/i })).toBeDisabled()

    await user.type(screen.getByTestId('cc-host'), 'db.example.com')
    await user.type(screen.getByTestId('cc-dbname'), 'appdb')
    await user.type(screen.getByTestId('cc-admin_username'), 'postgres')
    await user.type(screen.getByTestId('cc-target_role'), 'app_role')
    await user.click(screen.getByTestId('cc-admin_secret_id'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    expect(screen.getByRole('button', { name: /create policy/i })).not.toBeDisabled()
  })
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx`
Expected: the three new tests FAIL (no `cc-*` fields rendered; submit-disabled logic not schema-aware). Task 1's dropdown test still passes.

- [ ] **Step 3: Add config-assembly + validation helpers**

In `rotation-policies.tsx`, immediately after `seedConnectorConfig` (added in Task 1), add:

```tsx
// Assemble the backend connector_config from the string bag: coerce port to a
// number, tls to a boolean, and drop empty optional values.
function buildConnectorConfig(type: string, bag: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const field of CONNECTOR_FIELDS[type] ?? []) {
    const raw = bag[field.key]
    if (field.type === 'checkbox') {
      if (raw === 'true') out[field.key] = true
      continue
    }
    if (raw === undefined || raw === '') continue
    if (field.type === 'number') {
      const n = parseInt(raw, 10)
      out[field.key] = Number.isNaN(n) ? raw : n
    } else {
      out[field.key] = raw
    }
  }
  return out
}

// Load a saved policy's connector_config back into the string bag for editing.
function configToBag(cfg: Record<string, unknown>): Record<string, string> {
  const bag: Record<string, string> = {}
  for (const [k, v] of Object.entries(cfg ?? {})) {
    bag[k] = typeof v === 'boolean' ? (v ? 'true' : '') : String(v)
  }
  return bag
}

function connectorConfigValid(f: PolicyFormState): boolean {
  if (f.connectorType === 'directory') return !!f.directoryId && !!f.username
  if (SCHEMA_CONNECTORS.includes(f.connectorType)) {
    return (CONNECTOR_FIELDS[f.connectorType] ?? []).every(
      (field) => !field.required || !!f.connectorConfig[field.key],
    )
  }
  return true // generate_only needs no config
}
```

- [ ] **Step 4: Wire `formToInput`, `policyToForm`, and `isFormValid`**

Replace the `connectorConfig` computation in `formToInput` (~line 147-150) with:

```tsx
  const connectorConfig: Record<string, unknown> =
    f.connectorType === 'directory'
      ? { directory_id: f.directoryId, username: f.username }
      : SCHEMA_CONNECTORS.includes(f.connectorType)
        ? buildConnectorConfig(f.connectorType, f.connectorConfig)
        : {}
```

In `policyToForm` (~line 129-143 return object), add the bag alongside the existing fields:

```tsx
    directoryId: cfg.directory_id ?? '',
    username: cfg.username ?? '',
    connectorConfig: ['ssh', 'ssh_key', 'postgres', 'mysql'].includes(p.connector_type)
      ? configToBag(p.connector_config as Record<string, unknown>)
      : {},
```

Replace the `isFormValid` expression (~line 252-255) with:

```tsx
  const isFormValid = !!form.secretId && !!form.connectorType && connectorConfigValid(form)
```

- [ ] **Step 5: Add the dynamic connector-fields render block + the field component**

After the directory-specific fields block (`{form.connectorType === 'directory' && (...)}`, ends ~line 482), add:

```tsx
            {/* Schema-driven connector fields (ssh / ssh_key / postgres / mysql) */}
            {SCHEMA_CONNECTORS.includes(form.connectorType) && (
              <div className="space-y-3">
                {CONNECTOR_FIELDS[form.connectorType].map((field) => (
                  <ConnectorFieldInput
                    key={field.key}
                    field={field}
                    value={form.connectorConfig[field.key] ?? ''}
                    secrets={secrets}
                    onChange={(val) =>
                      setForm((f) => ({
                        ...f,
                        connectorConfig: { ...f.connectorConfig, [field.key]: val },
                      }))
                    }
                  />
                ))}
              </div>
            )}
```

Then add the `ConnectorFieldInput` component at the bottom of the file (module scope, after the page component):

```tsx
function ConnectorFieldInput({
  field,
  value,
  secrets,
  onChange,
}: {
  field: ConnectorField
  value: string
  secrets: VaultSecretMeta[]
  onChange: (val: string) => void
}) {
  const label = `${field.label}${field.required ? ' *' : ''}`
  const testId = `cc-${field.key}`

  if (field.type === 'secret') {
    return (
      <div>
        <label className="text-sm font-medium">{label}</label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger className="mt-1" data-testid={testId}>
            <SelectValue placeholder="Select a secret" />
          </SelectTrigger>
          <SelectContent>
            {secrets.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    )
  }

  if (field.type === 'select') {
    return (
      <div>
        <label className="text-sm font-medium">{label}</label>
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger className="mt-1" data-testid={testId}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {(field.options ?? []).map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    )
  }

  if (field.type === 'textarea') {
    return (
      <div>
        <label className="text-sm font-medium">{label}</label>
        <textarea
          className="mt-1 w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
          rows={2}
          placeholder={field.placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          data-testid={testId}
        />
      </div>
    )
  }

  if (field.type === 'checkbox') {
    return (
      <div className="flex items-center gap-3">
        <input
          type="checkbox"
          id={testId}
          checked={value === 'true'}
          onChange={(e) => onChange(e.target.checked ? 'true' : '')}
          data-testid={testId}
        />
        <label htmlFor={testId} className="text-sm font-medium">
          {field.label}
        </label>
      </div>
    )
  }

  // 'text' | 'number'
  return (
    <div>
      <label className="text-sm font-medium">{label}</label>
      <Input
        className="mt-1"
        type={field.type === 'number' ? 'number' : 'text'}
        placeholder={field.placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        data-testid={testId}
      />
    </div>
  )
}
```

- [ ] **Step 6: Run the full page test suite to verify all pass**

Run: `cd /home/cmit/openidx/web/admin-console && npx vitest run src/pages/rotation-policies.test.tsx`
Expected: PASS all — the three new tests plus every pre-existing test (dropdown, directory-fields, createPolicy).

- [ ] **Step 7: Type-check + build the console**

Run: `cd /home/cmit/openidx/web/admin-console && npm run build`
Expected: `tsc -b` clean (no unused symbols, no type errors) and vite build succeeds.

- [ ] **Step 8: Commit**

```bash
cd /home/cmit/openidx
git add web/admin-console/src/pages/rotation-policies.tsx web/admin-console/src/pages/rotation-policies.test.tsx
git commit -m "feat(admin-console): dynamic connector config fields for ssh/ssh_key/postgres/mysql rotation policies

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- Declarative `CONNECTOR_FIELDS` schema → Task 1 Step 3. ✓
- Config-bag form state + seed defaults → Task 1 Steps 5-6. ✓
- Dropdown extended to 6 + label/color maps → Task 1 Steps 4, 6. ✓
- Dynamic field render (secret/select/textarea/checkbox/text/number) → Task 2 Step 5. ✓
- `admin_secret_id` reuses the `secrets` list → `ConnectorFieldInput` `secret` branch. ✓
- `formToInput` (port→number, tls→bool, drop empties), `policyToForm` round-trip, `isFormValid` schema-driven → Task 2 Steps 3-4. ✓
- Backend/OpenAPI unchanged; directory + generate_only untouched → confirmed (branches preserved). ✓
- Tests: mysql reveal+submit config, ssh_key host_key+secret picker, submit-disabled-until-required → Task 2 Step 1; dropdown test updated → Task 1 Step 1. ✓
- Out of scope (cloud-IAM, secret creation shortcut, rotate-now changes) → not touched. ✓

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step is complete. ✓

**3. Type consistency:** `ConnectorField`/`ConnectorFieldType`, `CONNECTOR_FIELDS`, `SCHEMA_CONNECTORS`, `seedConnectorConfig`, `buildConnectorConfig`, `configToBag`, `connectorConfigValid`, and the `connectorConfig` state field are named identically across Tasks 1-2. `ConnectorFieldInput` props (`field`, `value`, `secrets`, `onChange`) match the call site. Field keys (`host`, `port`, `admin_secret_id`, `admin_username`, `host_key`, `target_role`, `target_user`, `target_host`, `dbname`, `sslmode`, `tls`, `admin_auth`, `username`) match the backend `*ConfigFromMap` keys from the spec table. `data-testid={`cc-${key}`}` matches the test selectors. ✓
