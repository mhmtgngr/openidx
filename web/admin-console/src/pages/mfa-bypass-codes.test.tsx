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

import { MFABypassCodesPage } from './mfa-bypass-codes'
import { api } from '../lib/api'

const activeCode = {
  id: 'bp-1',
  user_id: 'u-1',
  user_email: 'alice@example.com',
  reason: 'Lost phone — temporary access until replacement arrives',
  generated_by: 'admin-1',
  generator_email: 'admin@example.com',
  valid_from: '2026-06-09T00:00:00Z',
  valid_until: '2026-06-10T00:00:00Z',
  max_uses: 1,
  use_count: 0,
  status: 'active',
  created_at: '2026-06-09T00:00:00Z',
}

const usedCode = {
  ...activeCode,
  id: 'bp-2',
  user_id: 'u-2',
  user_email: 'bob@example.com',
  reason: 'Onboarding bypass',
  status: 'used',
  use_count: 1,
}

const expiredCode = {
  ...activeCode,
  id: 'bp-3',
  user_id: 'u-3',
  user_email: 'carol@example.com',
  reason: 'Old approval',
  status: 'expired',
}

const revokedCode = {
  ...activeCode,
  id: 'bp-4',
  user_id: 'u-4',
  user_email: 'dave@example.com',
  reason: 'Cancelled',
  status: 'revoked',
}

function routeGet(url: string) {
  if (url.includes('/mfa/bypass-codes/audit')) return Promise.resolve({ entries: [] })
  if (url.includes('/mfa/bypass-codes')) {
    return Promise.resolve({ codes: [activeCode, usedCode, expiredCode, revokedCode] })
  }
  return Promise.resolve({})
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('MFABypassCodesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + the Generate Code and Audit Log buttons', async () => {
    render(<MFABypassCodesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('MFA Bypass Codes')).toBeInTheDocument()
    expect(screen.getByText(/generate temporary bypass codes for users/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /generate code/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /audit log/i })).toBeInTheDocument()
  })

  it('shows the security warning banner', async () => {
    render(<MFABypassCodesPage />, { wrapper: createWrapper() })
    await screen.findByText('MFA Bypass Codes')
    expect(screen.getByText('Security Notice')).toBeInTheDocument()
    expect(
      screen.getByText(/bypass codes allow users to skip mfa verification/i),
    ).toBeInTheDocument()
  })

  it('derives the four stat counters from the codes list (active / used / expired+revoked)', async () => {
    render(<MFABypassCodesPage />, { wrapper: createWrapper() })
    // Wait for the table data to load so the derived counts settle.
    expect(await screen.findByText('alice@example.com')).toBeInTheDocument()

    // Card titles — "Active" / "Used" collide with status badge labels in
    // the rows, so disambiguate via getAllByText.
    expect(screen.getByText('Total Codes')).toBeInTheDocument()
    expect(screen.getAllByText('Active').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Used').length).toBeGreaterThan(0)
    expect(screen.getByText('Expired/Revoked')).toBeInTheDocument()

    // 4 codes total — fixture has 1 active, 1 used, and 2 expired/revoked.
    const fours = screen.getAllByText('4')
    expect(fours.length).toBeGreaterThan(0)
    // The expired/revoked count is 2.
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('lists each code row with user email and reason', async () => {
    render(<MFABypassCodesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
    expect(screen.getByText('carol@example.com')).toBeInTheDocument()
    expect(screen.getByText('dave@example.com')).toBeInTheDocument()

    // Reason text from the active code row
    expect(
      screen.getByText(/lost phone — temporary access until replacement arrives/i),
    ).toBeInTheDocument()

    // Each row has its own status badge — "Expired" and "Revoked" only
    // appear in the rows (no card with that exact text), so we assert
    // those directly. "Active"/"Used" overlap card titles and are
    // covered in the counters test above.
    expect(screen.getByText('Expired')).toBeInTheDocument()
    expect(screen.getByText('Revoked')).toBeInTheDocument()
  })

  it('opens the Generate Code dialog when the button is clicked', async () => {
    const user = userEvent.setup()
    render(<MFABypassCodesPage />, { wrapper: createWrapper() })
    await screen.findByText('MFA Bypass Codes')

    await user.click(screen.getByRole('button', { name: /generate code/i }))
    // The dialog body has a textarea whose placeholder is
    // "Why is this bypass code needed?" — anchor on it rather than the
    // dialog title (which duplicates the trigger button's name).
    expect(
      await screen.findByPlaceholderText(/why is this bypass code needed/i),
    ).toBeInTheDocument()
  })

  it('shows the empty state when no codes exist', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.includes('/mfa/bypass-codes/audit')) {
        return Promise.resolve({ entries: [] }) as ReturnType<typeof api.get>
      }
      return Promise.resolve({ codes: [] }) as ReturnType<typeof api.get>
    })
    render(<MFABypassCodesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('No bypass codes found')).toBeInTheDocument()
  })
})
