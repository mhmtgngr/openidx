import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { HardwareTokensPage } from './hardware-tokens'
import { api } from '../lib/api'

const availableToken = {
  id: 't-1',
  serial_number: '12345678',
  name: 'YubiKey 5 NFC #1',
  token_type: 'yubikey_otp',
  status: 'available',
  use_count: 0,
  last_used_at: null,
}

const assignedToken = {
  id: 't-2',
  serial_number: '87654321',
  name: 'YubiKey 5C #2',
  token_type: 'yubikey_otp',
  status: 'assigned',
  use_count: 47,
  last_used_at: '2026-06-01T00:00:00Z',
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('HardwareTokensPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockResolvedValue({
      tokens: [availableToken, assignedToken],
    })
  })

  it('renders the heading + subtitle + Add Token button', async () => {
    render(<HardwareTokensPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Hardware Tokens')).toBeInTheDocument()
    expect(
      screen.getByText(/manage yubikey and oath hardware tokens/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /add token/i }),
    ).toBeInTheDocument()
  })

  it('shows the four stat cards (Total / Available / Assigned / Revoked-Lost)', async () => {
    render(<HardwareTokensPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('Total Tokens')).toBeInTheDocument()
    // "Available" / "Assigned" collide with Select-trigger options + row badges.
    expect(screen.getAllByText('Available').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Assigned').length).toBeGreaterThan(0)
    expect(screen.getByText('Revoked/Lost')).toBeInTheDocument()
  })

  it('lists token rows with serial + name', async () => {
    render(<HardwareTokensPage />, { wrapper: createWrapper() })

    expect(await screen.findByText('12345678')).toBeInTheDocument()
    expect(screen.getByText('87654321')).toBeInTheDocument()
    expect(screen.getByText('YubiKey 5 NFC #1')).toBeInTheDocument()
    expect(screen.getByText('YubiKey 5C #2')).toBeInTheDocument()
  })

  it('opens the Add Token dialog when the header button is clicked', async () => {
    const user = userEvent.setup()
    render(<HardwareTokensPage />, { wrapper: createWrapper() })
    await screen.findByText('12345678')

    await user.click(screen.getByRole('button', { name: /add token/i }))

    expect(
      await screen.findByPlaceholderText(/e.g., 12345678/i),
    ).toBeInTheDocument()
    expect(
      screen.getByPlaceholderText(/e.g., yubikey 5 nfc #1/i),
    ).toBeInTheDocument()
  })

  it('renders the empty state when no tokens match', async () => {
    vi.mocked(api.get).mockResolvedValue({ tokens: [] })

    render(<HardwareTokensPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no hardware tokens found/i),
    ).toBeInTheDocument()
  })
})
