import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const { toast } = vi.hoisted(() => ({ toast: vi.fn() }))

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    getWithHeaders: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    pam: { listEntries: vi.fn() },
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast }),
}))

import { EngagementsTab, type Engagement } from './vendor-engagements'
import { api } from '../lib/api'

const running: Engagement = {
  id: 'e-1', vendor_org_id: 'v-1', vendor_name: 'Acme Field Service', sponsor_user_id: 's-1', sponsor_name: 'Selin Sponsor',
  title: 'Firmware upgrade', purpose: '', ticket_ref: 'CHG-1', starts_at: '2026-10-11T08:00:00Z', ends_at: '2099-10-11T18:00:00Z',
  member_user_ids: ['u-1'], status: 'open', state: 'running',
  targets: [{ target_type: 'pam_entry', target_id: 'p-1', target_name: 'core-db' }],
  created_at: '2026-10-11T08:00:00Z', updated_at: '2026-10-11T08:00:00Z',
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}><EngagementsTab /></QueryClientProvider>)
}

describe('EngagementsTab', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation(async (url: string) => {
      if (url.startsWith('/api/v1/identity/engagements')) return { engagements: [running] }
      if (url === '/api/v1/identity/vendor-orgs') {
        return { vendor_organizations: [{ id: 'v-1', name: 'Acme Field Service', status: 'active', require_engagement: true }] }
      }
      if (url.startsWith('/api/v1/identity/external-users')) {
        return { external_users: [{ id: 'u-1', username: 'ayse.vendor', first_name: 'Ayşe', last_name: 'Vendor', status: 'active' }] }
      }
      return []
    })
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: [{ id: 'a-1', name: 'Plant HMI' }], headers: {} } as never)
    vi.mocked(api.pam.listEntries).mockResolvedValue({ entries: [] } as never)
    vi.mocked(api.post).mockResolvedValue({} as never)
  })

  it('lists an engagement with its state, vendor and what it covers', async () => {
    renderTab()
    const row = (await screen.findByText('Firmware upgrade')).closest('tr') as HTMLElement
    expect(within(row).getByText('Acme Field Service')).toBeInTheDocument()
    expect(within(row).getByText('Running')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })

  it('creates an engagement with its vendor, window, people and targets', async () => {
    const user = userEvent.setup()
    renderTab()
    await user.click(await screen.findByRole('button', { name: /New engagement/ }))
    const vendor = await screen.findByLabelText('Vendor organization')
    await waitFor(() => expect(within(vendor).getByText('Acme Field Service')).toBeInTheDocument())
    await user.selectOptions(vendor, 'v-1')
    await user.type(screen.getByLabelText('Title'), 'Panel swap')
    fireEvent.change(screen.getByLabelText('Ends'), { target: { value: '2099-01-02T10:00' } })
    await user.click(await screen.findByLabelText('Ayşe Vendor'))
    const target = screen.getByLabelText('Target')
    await waitFor(() => expect(within(target).getByText('Plant HMI')).toBeInTheDocument())
    await user.selectOptions(target, 'a-1')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.post).toHaveBeenCalled())
    const [url, body] = vi.mocked(api.post).mock.calls[0] as [string, Record<string, unknown>]
    expect(url).toBe('/api/v1/identity/vendor-orgs/v-1/engagements')
    expect(body).toMatchObject({
      title: 'Panel swap',
      member_user_ids: ['u-1'],
      targets: [{ target_type: 'application', target_id: 'a-1' }],
    })
    expect(body.ends_at).toBe(new Date('2099-01-02T10:00').toISOString())
    expect(body).not.toHaveProperty('starts_at')
  })
})
