import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
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

import { ExternalUsersPage, type ExternalUser, type VendorOrg } from './external-users'
import { api } from '../lib/api'

const future = (days: number) => new Date(Date.now() + days * 86400000).toISOString()

const account = (over: Partial<ExternalUser>): ExternalUser => ({
  id: 'u-active',
  username: 'ayse.vendor',
  email: 'ayse@supplier.example.test',
  first_name: 'Ayşe',
  last_name: 'Vendor',
  status: 'active',
  enabled: true,
  vendor_org_id: 'v-1',
  vendor_name: 'Acme Field Service',
  sponsor_user_id: 's-1',
  sponsor_name: 'Selin Sponsor',
  account_expires_at: future(40),
  created_at: '2026-09-01T00:00:00Z',
  expiring_soon: false,
  has_strong_factor: true,
  ...over,
})

const accounts: ExternalUser[] = [
  account({}),
  account({ id: 'u-nofactor', username: 'no.factor', first_name: 'Nur', last_name: 'Factorless', has_strong_factor: false, expiring_soon: true, account_expires_at: future(5) }),
  account({ id: 'u-suspended', username: 'sus.pended', first_name: 'Sena', last_name: 'Suspended', status: 'suspended', enabled: false, reactivate_until: future(3) }),
  account({ id: 'u-expired', username: 'ex.pired', first_name: 'Emre', last_name: 'Expired', status: 'expired', enabled: false }),
  account({ id: 'u-late', username: 'past.grace', first_name: 'Pelin', last_name: 'Late', status: 'suspended', enabled: false, reactivate_until: future(-1) }),
]

const vendors: VendorOrg[] = [
  {
    id: 'v-1', name: 'Acme Field Service', status: 'active', contact_name: '', contact_email: '',
    contract_end: '2099-12-31', allowed_email_domains: ['supplier.example.test'], default_expiry_days: 90,
    default_sponsor_user_id: '', notes: '', external_users: { active: 2, suspended: 1, expired: 1 },
  },
  {
    id: 'v-2', name: 'Paused Vendor', status: 'suspended', contact_name: '', contact_email: '',
    allowed_email_domains: [], default_expiry_days: 30, default_sponsor_user_id: '', notes: '',
  },
  {
    id: 'v-3', name: 'Listed Vendor', status: 'active', contact_name: '', contact_email: '',
    allowed_email_domains: ['listed.example.test'], default_expiry_days: 30, default_sponsor_user_id: '', notes: '',
    closed_list: true,
  },
]

const targets = [
  { id: 't-1', target_type: 'pam_entry', target_id: 'e-1', target_name: 'prod-db', created_at: '2026-09-01T00:00:00Z' },
]

const invitations = [
  { id: 'i-1', email: 'new@supplier.example.test', token: 'tok-ext', status: 'pending', expires_at: future(7), user_type: 'external', vendor_org_id: 'v-1', account_expires_at: future(90) },
  { id: 'i-2', email: 'staff@example.test', token: 'tok-int', status: 'pending', expires_at: future(7), user_type: 'internal' },
]

function routeGet(url: string) {
  if (url.endsWith('/targets')) return Promise.resolve({ targets })
  if (url.startsWith('/api/v1/identity/vendor-orgs')) return Promise.resolve({ vendor_organizations: vendors })
  if (url.startsWith('/api/v1/identity/external-users')) return Promise.resolve({ external_users: accounts })
  if (url.startsWith('/api/v1/identity/invitations')) return Promise.resolve({ invitations })
  return Promise.resolve({})
}

function routeGetWithHeaders(url: string) {
  if (url.startsWith('/api/v1/identity/users')) {
    return Promise.resolve({
      data: [
        { id: 's-1', userName: 'selin', name: { givenName: 'Selin', familyName: 'Sponsor' }, emails: [{ value: 'selin@example.test' }], enabled: true, userType: 'internal' },
        { id: 's-2', userName: 'deniz', name: { givenName: 'Deniz', familyName: 'Internal' }, emails: [{ value: 'deniz@example.test' }], enabled: true },
        { id: 'u-active', userName: 'ayse.vendor', enabled: true, userType: 'external' },
        { id: 's-off', userName: 'left.company', enabled: false, userType: 'internal' },
      ],
      headers: {},
    })
  }
  if (url.startsWith('/api/v1/identity/groups')) {
    return Promise.resolve({
      data: [
        { id: 'g-open', displayName: 'vendor-support', attributes: { externalAllowed: 'true' } },
        { id: 'g-closed', displayName: 'finance', attributes: { externalAllowed: 'false' } },
      ],
      headers: {},
    })
  }
  return Promise.resolve({ data: [], headers: {} })
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ExternalUsersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function openMenu(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await screen.findByRole('button', { name: `Actions for ${name}` }))
}

describe('ExternalUsersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as never)
    vi.mocked(api.getWithHeaders).mockImplementation((url: string) => routeGetWithHeaders(url) as never)
    vi.mocked(api.post).mockResolvedValue({} as never)
  })

  it('lists each account with the state the identity service reports', async () => {
    renderPage()
    expect(await screen.findByText('Ayşe Vendor')).toBeInTheDocument()
    expect(screen.getAllByText('Acme Field Service').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Selin Sponsor').length).toBeGreaterThan(0)

    const noFactorRow = screen.getByText('Nur Factorless').closest('tr')!
    expect(within(noFactorRow).getByText('No second factor')).toBeInTheDocument()
    expect(within(noFactorRow).getByText('Ends soon')).toBeInTheDocument()

    const activeRow = screen.getByText('Ayşe Vendor').closest('tr')!
    expect(within(activeRow).queryByText('No second factor')).not.toBeInTheDocument()
    expect(within(activeRow).queryByText('Ends soon')).not.toBeInTheDocument()

    const suspendedRow = screen.getByText('Sena Suspended').closest('tr')!
    expect(within(suspendedRow).getByText('Suspended')).toBeInTheDocument()
    expect(within(suspendedRow).getByText(/can be reactivated until/i)).toBeInTheDocument()
  })

  it('asks the identity service for the chosen status', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('Ayşe Vendor')
    await user.selectOptions(screen.getByLabelText('Status'), 'suspended')
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith('/api/v1/identity/external-users?status=suspended'),
    )
  })

  it('offers only the moves the account state allows', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('Ayşe Vendor')

    await openMenu(user, 'Ayşe Vendor')
    for (const item of ['Extend', 'Change sponsor', 'Suspend', 'Disable']) {
      expect(await screen.findByRole('menuitem', { name: item })).toBeInTheDocument()
    }
    expect(screen.queryByRole('menuitem', { name: 'Reactivate' })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')

    await openMenu(user, 'Sena Suspended')
    expect(await screen.findByRole('menuitem', { name: 'Reactivate' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Suspend' })).not.toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Change sponsor' })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')

    // Past the grace period a suspension can only be ended for good.
    await openMenu(user, 'Pelin Late')
    expect(await screen.findByRole('menuitem', { name: 'Disable' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Reactivate' })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')

    // An expired account is final: nothing to offer.
    expect(screen.queryByRole('button', { name: 'Actions for Emre Expired' })).not.toBeInTheDocument()
  })

  it('suspends only with a reason, and sends it', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('Ayşe Vendor')
    await openMenu(user, 'Ayşe Vendor')
    await user.click(await screen.findByRole('menuitem', { name: 'Suspend' }))

    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Suspend' })
    expect(confirm).toBeDisabled()
    await user.click(confirm)
    expect(api.post).not.toHaveBeenCalled()

    await user.type(within(dialog).getByRole('textbox'), 'contract paused')
    await user.click(confirm)
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/identity/external-users/u-active/suspend', { reason: 'contract paused' }),
    )
  })

  it('extends by days with a reason, and shows the refusal the API gives', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockRejectedValueOnce({
      response: { data: { error: 'the account expiry may not pass the vendor\'s contract end', code: 'external_expiry_invalid' } },
    })
    renderPage()
    await screen.findByText('Ayşe Vendor')
    await openMenu(user, 'Ayşe Vendor')
    await user.click(await screen.findByRole('menuitem', { name: 'Extend' }))

    const dialog = await screen.findByRole('dialog')
    const days = within(dialog).getByLabelText('Days to add')
    await user.clear(days)
    await user.type(days, '45')
    const submit = within(dialog).getByRole('button', { name: 'Extend' })
    expect(submit).toBeDisabled()
    await user.type(within(dialog).getByLabelText(/reason/i), 'project extended')
    await user.click(submit)

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/identity/external-users/u-active/extend', { extend_days: 45, reason: 'project extended' }),
    )
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({
        description: "the account expiry may not pass the vendor's contract end",
        variant: 'destructive',
      })),
    )
  })

  it('reactivates with a new sponsor chosen from enabled internal users only', async () => {
    const user = userEvent.setup()
    renderPage()
    await screen.findByText('Sena Suspended')
    await openMenu(user, 'Sena Suspended')
    await user.click(await screen.findByRole('menuitem', { name: 'Reactivate' }))

    const dialog = await screen.findByRole('dialog')
    const sponsor = within(dialog).getByLabelText('Sponsor') as HTMLSelectElement
    await waitFor(() => expect(within(sponsor).getAllByRole('option').length).toBe(3))
    const offered = within(sponsor).getAllByRole('option').map((o) => (o as HTMLOptionElement).value)
    expect(offered).toEqual(['', 's-1', 's-2'])

    await user.selectOptions(sponsor, 's-2')
    await user.type(within(dialog).getByLabelText(/reason/i), 'new owner')
    await user.click(within(dialog).getByRole('button', { name: 'Reactivate' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/identity/external-users/u-suspended/reactivate', { sponsor_user_id: 's-2', reason: 'new owner' }),
    )
  })

  it('lists external invitations only and invites with the vendor and the open groups', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockResolvedValueOnce({ id: 'i-3', token: 'tok-new', email: 'mert@supplier.example.test' } as never)
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Invitations' }))
    expect(await screen.findByText('new@supplier.example.test')).toBeInTheDocument()
    expect(screen.queryByText('staff@example.test')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /invite external user/i }))
    const dialog = await screen.findByRole('dialog')
    const vendorSelect = within(dialog).getByLabelText('Vendor organization')
    // Only an active vendor can take an invitation.
    expect(within(vendorSelect).queryByRole('option', { name: 'Paused Vendor' })).not.toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('Email address'), 'mert@supplier.example.test')
    await user.selectOptions(vendorSelect, 'v-1')
    // Only the groups opened to external users are offered.
    expect(within(dialog).queryByLabelText('finance')).not.toBeInTheDocument()
    await user.click(await within(dialog).findByLabelText('vendor-support'))
    await user.click(within(dialog).getByRole('button', { name: /invite external user/i }))

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/identity/invitations', {
        email: 'mert@supplier.example.test',
        user_type: 'external',
        vendor_org_id: 'v-1',
        groups: ['g-open'],
      }),
    )
    const link = await within(dialog).findByLabelText('Invitation link')
    expect((link as HTMLInputElement).value).toMatch(/\/accept-invite\?token=tok-new$/)
  })

  it('closes a vendor only with a reason', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Vendor organizations' }))
    const row = (await screen.findByText('supplier.example.test')).closest('tr')!
    expect(within(row).getByText(/Active: 2/)).toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: 'Close' }))

    const dialog = await screen.findByRole('alertdialog')
    const confirm = within(dialog).getByRole('button', { name: 'Close' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'contract ended')
    await user.click(confirm)
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/identity/vendor-orgs/v-1/close', { reason: 'contract ended' }),
    )
  })

  it('puts a vendor on a closed list from its form', async () => {
    const user = userEvent.setup()
    vi.mocked(api.put).mockResolvedValue({} as never)
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Vendor organizations' }))
    const row = (await screen.findByText('supplier.example.test')).closest('tr')!
    expect(within(row).queryByRole('button', { name: 'Targets' })).not.toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: 'Edit' }))
    await user.click(await screen.findByRole('checkbox', { name: /closed list/i }))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/identity/vendor-orgs/v-1', expect.objectContaining({ closed_list: true })),
    )
  })

  it('lists, opens and closes what is open to a vendor on a closed list', async () => {
    const user = userEvent.setup()
    vi.mocked(api.pam.listEntries).mockResolvedValue({ entries: [{ id: 'e-1', name: 'prod-db' }, { id: 'e-2', name: 'jump-01' }] } as never)
    vi.mocked(api.delete).mockResolvedValue({} as never)
    renderPage()
    await user.click(screen.getByRole('tab', { name: 'Vendor organizations' }))
    const row = (await screen.findByText('listed.example.test')).closest('tr')!
    expect(within(row).getByText('Closed list')).toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: 'Targets' }))

    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('prod-db')).toBeInTheDocument()
    // An entry already open is not offered again.
    const picker = await within(dialog).findByLabelText('Target')
    await waitFor(() => expect(within(picker).getByRole('option', { name: 'jump-01' })).toBeInTheDocument())
    expect(within(picker).queryByRole('option', { name: 'prod-db' })).not.toBeInTheDocument()
    await user.selectOptions(picker, 'e-2')
    await user.click(within(dialog).getByRole('button', { name: 'Open' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/identity/vendor-orgs/v-3/targets', { target_type: 'pam_entry', target_id: 'e-2' }),
    )
    await user.click(within(dialog).getByRole('button', { name: 'Withdraw' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('/api/v1/identity/vendor-orgs/v-3/targets/t-1'))
  })
})
