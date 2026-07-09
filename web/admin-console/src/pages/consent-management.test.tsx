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

import { ConsentManagementPage } from './consent-management'
import { api } from '../lib/api'

const consent = {
  id: 'c-1',
  user_id: 'u-1',
  username: 'alice@example.com',
  consent_type: 'marketing_emails',
  version: '1.0',
  granted: true,
  granted_at: '2026-01-01T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
}

const dsar = {
  id: 'd-1abcdef0', // first 8 chars are rendered as 'd-1abcde…'
  user_id: 'u-1',
  username: 'bob@example.com',
  request_type: 'export',
  status: 'pending',
  reason: 'GDPR Article 15 request',
  due_date: '2026-02-01T00:00:00Z',
  created_at: '2026-01-02T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
}

const retentionPolicy = {
  id: 'rp-1',
  name: 'Audit log retention',
  data_category: 'audit_events',
  retention_days: 365,
  action: 'delete',
  enabled: true,
  created_at: '2026-01-03T00:00:00Z',
  updated_at: '2026-01-03T00:00:00Z',
}

const assessment = {
  id: 'a-1',
  title: 'New user analytics pipeline',
  description: 'DPIA for the v2 analytics ingestion',
  risk_level: 'medium',
  status: 'draft',
  created_at: '2026-01-04T00:00:00Z',
  updated_at: '2026-01-04T00:00:00Z',
}

function routeGet(url: string) {
  if (url.includes('/privacy/consents')) return Promise.resolve({ data: [consent] })
  if (url.includes('/privacy/dsars')) return Promise.resolve({ data: [dsar] })
  if (url.includes('/privacy/retention')) return Promise.resolve({ data: [retentionPolicy] })
  if (url.includes('/privacy/assessments')) return Promise.resolve({ data: [assessment] })
  return Promise.resolve({ data: [] })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ConsentManagementPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the page heading and all four tabs', async () => {
    render(<ConsentManagementPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Consent Management')).toBeInTheDocument()
    // Tab labels (each comes from the tabs const at the top of the file)
    expect(screen.getByRole('button', { name: /user consents/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /data subject requests/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retention policies/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /impact assessments/i })).toBeInTheDocument()
  })

  it('shows the consent row for the loaded consent', async () => {
    render(<ConsentManagementPage />, { wrapper: createWrapper() })
    // consent_type is rendered with underscores converted to spaces and the
    // `capitalize` CSS class — so the DOM text is "marketing emails".
    expect(await screen.findByText('marketing emails')).toBeInTheDocument()
    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
  })

  it('switches to Data Subject Requests tab and shows the export DSAR', async () => {
    const user = userEvent.setup()
    render(<ConsentManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('Consent Management')

    await user.click(screen.getByRole('button', { name: /data subject requests/i }))
    // Tab heading from the DSARs tab
    expect(await screen.findByText(/data subject access requests/i)).toBeInTheDocument()
    // The DSAR's username from the row
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
    // Pending status surfaces a "Process" button on each pending row
    expect(screen.getByRole('button', { name: /process/i })).toBeInTheDocument()
  })

  it('switches to Retention Policies tab and shows the policy row', async () => {
    const user = userEvent.setup()
    render(<ConsentManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('Consent Management')

    await user.click(screen.getByRole('button', { name: /retention policies/i }))
    expect(await screen.findByText('Audit log retention')).toBeInTheDocument()
  })

  it('switches to Impact Assessments tab and shows the assessment title', async () => {
    const user = userEvent.setup()
    render(<ConsentManagementPage />, { wrapper: createWrapper() })
    await screen.findByText('Consent Management')

    await user.click(screen.getByRole('button', { name: /impact assessments/i }))
    expect(await screen.findByText('New user analytics pipeline')).toBeInTheDocument()
  })
})
