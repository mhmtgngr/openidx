import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
    vault: {
      listSecrets: vi.fn(),
      createSecret: vi.fn(),
      getSecret: vi.fn(),
      newVersion: vi.fn(),
      deleteSecret: vi.fn(),
      reveal: vi.fn(),
      addGrant: vi.fn(),
      removeGrant: vi.fn(),
      listGrants: vi.fn(),
      listCheckouts: vi.fn(),
      listPolicies: vi.fn(),
      createPolicy: vi.fn(),
      getPolicy: vi.fn(),
      updatePolicy: vi.fn(),
      deletePolicy: vi.fn(),
      rotateNow: vi.fn(),
      listRotations: vi.fn(),
    },
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { RotationPoliciesPage } from './rotation-policies'
import { api } from '../lib/api'

const secretA = {
  id: 'sec-1',
  name: 'prod-db-password',
  type: 'password',
  current_version: 3,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-06-01T00:00:00Z',
}

const policyA = {
  id: 'pol-1',
  org_id: 'org-1',
  secret_id: 'sec-1',
  connector_type: 'generate_only',
  connector_config: {},
  generation_policy: { length: 24, upper: true, lower: true, digits: true, symbols: false },
  interval_seconds: 604800,
  rotate_on_checkout: false,
  enabled: true,
  last_status: 'success',
  last_run_at: '2026-06-01T00:00:00Z',
  next_run_at: '2026-06-08T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-06-01T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('RotationPoliciesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.vault.listPolicies).mockResolvedValue({ policies: [policyA] })
    vi.mocked(api.vault.listSecrets).mockResolvedValue({ secrets: [secretA] })
    vi.mocked(api.vault.createPolicy).mockResolvedValue(policyA)
    vi.mocked(api.vault.deletePolicy).mockResolvedValue(undefined)
  })

  it('renders the heading and New Policy button', async () => {
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Rotation Policies')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /new policy/i })).toBeInTheDocument()
  })

  it('lists policies with resolved secret name and interval', async () => {
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('prod-db-password')).toBeInTheDocument()
    // 604800s = 7d
    expect(screen.getByText('7d')).toBeInTheDocument()
    // connector type badge
    expect(screen.getByText('Generate-only')).toBeInTheDocument()
  })

  it('falls back to secret_id when secret is not in the list', async () => {
    vi.mocked(api.vault.listPolicies).mockResolvedValue({
      policies: [{ ...policyA, secret_id: 'unknown-sec' }],
    })
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('unknown-sec')).toBeInTheDocument()
  })

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

  it('directory fields appear only when connector type is directory', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    // Default is generate_only — directory fields should NOT be visible
    expect(screen.queryByTestId('directory-id-input')).not.toBeInTheDocument()
    expect(screen.queryByTestId('username-input')).not.toBeInTheDocument()

    // Switch to directory
    const connectorTrigger = screen.getByTestId('connector-select')
    await user.click(connectorTrigger)
    await user.click(screen.getByRole('option', { name: 'Directory' }))

    // Now they should be visible
    expect(screen.getByTestId('directory-id-input')).toBeInTheDocument()
    expect(screen.getByTestId('username-input')).toBeInTheDocument()

    // Switch back
    await user.click(connectorTrigger)
    await user.click(screen.getByRole('option', { name: 'Generate-only' }))
    expect(screen.queryByTestId('directory-id-input')).not.toBeInTheDocument()
  })

  it('calls createPolicy when form is submitted', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    // Select the secret
    const secretTrigger = screen.getByTestId('secret-select')
    await user.click(secretTrigger)
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    // Submit (generate_only needs no extra fields)
    await user.click(screen.getByRole('button', { name: /create policy/i }))

    await waitFor(() => {
      expect(vi.mocked(api.vault.createPolicy)).toHaveBeenCalledWith(
        expect.objectContaining({ secret_id: 'sec-1', connector_type: 'generate_only' })
      )
    })
  })

  it('MySQL connector reveals its fields and builds connector_config on submit', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'MySQL' }))

    expect(screen.getByTestId('cc-host')).toBeInTheDocument()
    expect(screen.getByTestId('cc-target_user')).toBeInTheDocument()

    await user.type(screen.getByTestId('cc-host'), 'db.example.com')
    await user.type(screen.getByTestId('cc-admin_username'), 'root')
    await user.type(screen.getByTestId('cc-target_user'), 'app_user')
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

  it('AWS IAM connector reveals its fields and builds connector_config on submit', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'AWS IAM' }))

    expect(screen.getByTestId('cc-target_user')).toBeInTheDocument()
    await user.type(screen.getByTestId('cc-target_user'), 'svc-rotated')
    await user.click(screen.getByTestId('cc-admin_secret_id'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    await waitFor(() => {
      expect(vi.mocked(api.vault.createPolicy)).toHaveBeenCalledWith(
        expect.objectContaining({
          connector_type: 'aws_iam',
          connector_config: expect.objectContaining({
            target_user: 'svc-rotated',
            admin_secret_id: 'sec-1',
            region: 'us-east-1',
          }),
        }),
      )
    })
  })

  it('SSH admin auth "SSH private key" submits admin_auth=private_key', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'SSH (password)' }))

    // fill required ssh fields
    await user.type(screen.getByTestId('cc-host'), 'ssh.example.com')
    await user.type(screen.getByTestId('cc-username'), 'svc')
    await user.type(screen.getByTestId('cc-admin_username'), 'root')
    await user.type(screen.getByTestId('cc-host_key'), 'ssh-ed25519 AAAA')
    await user.click(screen.getByTestId('cc-admin_secret_id'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    // switch admin auth to private key
    await user.click(screen.getByTestId('cc-admin_auth'))
    await user.click(screen.getByRole('option', { name: 'SSH private key' }))

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    await waitFor(() => {
      expect(vi.mocked(api.vault.createPolicy)).toHaveBeenCalledWith(
        expect.objectContaining({
          connector_type: 'ssh',
          connector_config: expect.objectContaining({ admin_auth: 'private_key' }),
        }),
      )
    })
  })

  it('submit stays disabled until a connector\'s required fields are filled', async () => {
    const user = userEvent.setup()
    render(<RotationPoliciesPage />, { wrapper: createWrapper() })
    await screen.findByText('Rotation Policies')

    await user.click(screen.getByRole('button', { name: /new policy/i }))
    await screen.findByText('New Rotation Policy')

    await user.click(screen.getByTestId('secret-select'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    await user.click(screen.getByTestId('connector-select'))
    await user.click(screen.getByRole('option', { name: 'PostgreSQL' }))

    expect(screen.getByRole('button', { name: /create policy/i })).toBeDisabled()

    await user.type(screen.getByTestId('cc-host'), 'db.example.com')
    await user.type(screen.getByTestId('cc-dbname'), 'appdb')
    await user.type(screen.getByTestId('cc-admin_username'), 'postgres')
    await user.type(screen.getByTestId('cc-target_role'), 'app_role')
    await user.click(screen.getByTestId('cc-admin_secret_id'))
    await user.click(screen.getByRole('option', { name: 'prod-db-password' }))

    expect(screen.getByRole('button', { name: /create policy/i })).not.toBeDisabled()
  })
})
