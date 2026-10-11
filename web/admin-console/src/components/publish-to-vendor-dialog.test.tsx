import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn() },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { PublishToVendorDialog } from './publish-to-vendor-dialog'
import { api } from '../lib/api'

function renderDialog() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <PublishToVendorDialog targetType="application" targetId="a-1" targetName="Plant HMI" open onOpenChange={() => {}} />
    </QueryClientProvider>,
  )
}

describe('PublishToVendorDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockResolvedValue({
      vendor_organizations: [
        { id: 'v-closed', name: 'Closed Co', status: 'active', closed_list: true },
        { id: 'v-open', name: 'Open Co', status: 'active', closed_list: false },
        { id: 'v-gone', name: 'Gone Co', status: 'closed' },
      ],
    })
    vi.mocked(api.post).mockResolvedValue({})
  })

  it('opens the resource to a closed-list vendor and starts an engagement for it', async () => {
    const user = userEvent.setup()
    renderDialog()
    const vendor = screen.getByLabelText('Vendor organization')
    await waitFor(() => expect(within(vendor).getByText('Closed Co')).toBeInTheDocument())
    expect(within(vendor).queryByText('Gone Co')).toBeNull()
    await user.selectOptions(vendor, 'v-closed')
    fireEvent.change(screen.getByLabelText('Ends'), { target: { value: '2099-01-02T10:00' } })
    await user.click(screen.getByRole('button', { name: 'Publish' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(2))
    expect(vi.mocked(api.post).mock.calls[0]).toEqual(['/api/v1/identity/vendor-orgs/v-closed/targets', { target_type: 'application', target_id: 'a-1' }])
    expect(vi.mocked(api.post).mock.calls[1][0]).toBe('/api/v1/identity/vendor-orgs/v-closed/engagements')
    expect(vi.mocked(api.post).mock.calls[1][1]).toMatchObject({ title: 'Plant HMI', targets: [{ target_type: 'application', target_id: 'a-1' }] })
  })

  it('only opens the target when no engagement is asked for', async () => {
    const user = userEvent.setup()
    renderDialog()
    const vendor = screen.getByLabelText('Vendor organization')
    await waitFor(() => expect(within(vendor).getByText('Closed Co')).toBeInTheDocument())
    await user.selectOptions(vendor, 'v-closed')
    await user.click(screen.getByLabelText(/Start an engagement now/))
    await user.click(screen.getByRole('button', { name: 'Publish' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(vi.mocked(api.post).mock.calls[0][0]).toBe('/api/v1/identity/vendor-orgs/v-closed/targets')
  })

  it('requires an engagement for a vendor without a closed list', async () => {
    const user = userEvent.setup()
    renderDialog()
    const vendor = screen.getByLabelText('Vendor organization')
    await waitFor(() => expect(within(vendor).getByText('Open Co')).toBeInTheDocument())
    await user.selectOptions(vendor, 'v-open')
    const engage = screen.getByLabelText(/Start an engagement now/) as HTMLInputElement
    expect(engage.checked).toBe(true)
    expect(engage.disabled).toBe(true)
    expect(screen.getByRole('button', { name: 'Publish' })).toBeDisabled()
  })
})
