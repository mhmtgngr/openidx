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
})
