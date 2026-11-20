import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))
// The site picker has its own tests; here it is just a default-site stub.
vi.mock('./site-select', () => ({ SiteSelect: () => null }))

import { PublishAppDialog } from './publish-app-dialog'
import { api } from '../lib/api'

const groups = [
  { id: 'g1', displayName: 'Engineering' },
  { id: 'g2', displayName: 'Operations' },
]

const result = (over: Record<string, unknown> = {}) => ({
  id: 'app-1',
  name: 'Wiki',
  service_name: 'openidx-net-app-1',
  url: 'https://wiki.corp.example/',
  groups: 1,
  users: 0,
  require_trusted_device: true,
  enforcement: { assignment: true, device_trust: 'enforce' },
  ...over,
})

function renderDialog(onPublished = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const utils = render(
    <QueryClientProvider client={qc}>
      <PublishAppDialog open onOpenChange={vi.fn()} onPublished={onPublished} />
    </QueryClientProvider>,
  )
  return { ...utils, onPublished }
}

async function fill(name = 'Wiki', address = 'https://wiki.corp.example', group = 'Engineering') {
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: name } })
  fireEvent.change(screen.getByLabelText('Address'), { target: { value: address } })
  if (group) fireEvent.click(await screen.findByRole('checkbox', { name: group }))
}

const publishButton = () => screen.getByRole('button', { name: 'Publish' })

describe('PublishAppDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockResolvedValue(groups)
    vi.mocked(api.post).mockResolvedValue(result())
  })

  it('publishes with the name, the address, the chosen groups and a trusted device by default', async () => {
    renderDialog()
    await fill()
    fireEvent.click(publishButton())
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(api.post).toHaveBeenCalledWith('/api/v1/access/network-resources/publish', {
      name: 'Wiki',
      description: '',
      address: 'https://wiki.corp.example',
      site: '',
      group_ids: ['g1'],
      user_ids: [],
      require_trusted_device: true,
    })
  })

  it('sends require_trusted_device false when the box is unticked', async () => {
    renderDialog()
    await fill()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Only from a trusted device' }))
    fireEvent.click(publishButton())
    await waitFor(() => expect(api.post).toHaveBeenCalled())
    expect(vi.mocked(api.post).mock.calls[0][1]).toMatchObject({ require_trusted_device: false })
  })

  it('keeps Publish disabled until there is a name, an address and at least one group', async () => {
    renderDialog()
    expect(publishButton()).toBeDisabled()
    await fill('Wiki', '', '')
    expect(publishButton()).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Address'), { target: { value: 'wiki.corp.example' } })
    expect(publishButton()).toBeDisabled() // no group yet
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Engineering' }))
    expect(publishButton()).toBeEnabled()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Engineering' }))
    expect(publishButton()).toBeDisabled()
  })

  it('shows a refused address under the Address field, with what is wrong', async () => {
    vi.mocked(api.post).mockRejectedValue({ response: { data: { code: 'invalid_address', error: 'invalid address: only http and https addresses can be published, not "ftp"' } } })
    renderDialog()
    await fill('Files', 'ftp://files.corp.example')
    fireEvent.click(publishButton())
    const msg = await screen.findByText(/only http and https/)
    expect(msg.closest('[data-field="address"]')).not.toBeNull()
  })

  it('says an already published name and port is taken, under the Address field', async () => {
    vi.mocked(api.post).mockRejectedValue({ response: { data: { code: 'already_published', error: 'already' } } })
    renderDialog()
    await fill()
    fireEvent.click(publishButton())
    const msg = await screen.findByText(/already published/i)
    expect(msg.closest('[data-field="address"]')).not.toBeNull()
  })

  it('shows what it cannot place on a field as a general error', async () => {
    vi.mocked(api.post).mockRejectedValue({ response: { data: { code: 'unknown_group', error: 'x' } } })
    renderDialog()
    await fill()
    fireEvent.click(publishButton())
    expect(await screen.findByRole('alert')).toHaveTextContent(/group/i)
  })

  it('says plainly when the install does not enforce assignments', async () => {
    vi.mocked(api.post).mockResolvedValue(result({ enforcement: { assignment: false, device_trust: 'enforce' } }))
    renderDialog()
    await fill()
    fireEvent.click(publishButton())
    expect(await screen.findByText(/does not enforce assignments yet/i)).toBeInTheDocument()
    expect(screen.queryByText(/device trust is not enforced/i)).toBeNull()
  })

  it('says plainly when device trust is not enforced, and names the gate', async () => {
    vi.mocked(api.post).mockResolvedValue(result({ enforcement: { assignment: true, device_trust: 'observe' } }))
    renderDialog()
    await fill()
    fireEvent.click(publishButton())
    expect(await screen.findByText(/device trust is not enforced yet \(observe\)/i)).toBeInTheDocument()
    expect(screen.queryByText(/does not enforce assignments/i)).toBeNull()
  })

  it('does not warn when the install enforces both', async () => {
    renderDialog()
    await fill()
    fireEvent.click(publishButton())
    expect(await screen.findByText(/hidden from the internet/i)).toBeInTheDocument()
    expect(screen.queryByText(/not enforce|not enforced/i)).toBeNull()
  })

  it('does not claim "trusted device" in the warning when none was required', async () => {
    vi.mocked(api.post).mockResolvedValue(result({ require_trusted_device: false, enforcement: { assignment: true, device_trust: 'off' } }))
    renderDialog()
    await fill()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Only from a trusted device' }))
    fireEvent.click(publishButton())
    expect(await screen.findByText(/hidden from the internet/i)).toBeInTheDocument()
    expect(screen.queryByText(/device trust is not enforced/i)).toBeNull()
  })

  it('calls onPublished after a successful publish', async () => {
    const { onPublished } = renderDialog()
    await fill()
    fireEvent.click(publishButton())
    await waitFor(() => expect(onPublished).toHaveBeenCalledTimes(1))
  })

  it('does not call onPublished when the publish is refused', async () => {
    vi.mocked(api.post).mockRejectedValue({ response: { data: { code: 'already_published', error: 'x' } } })
    const { onPublished } = renderDialog()
    await fill()
    fireEvent.click(publishButton())
    await screen.findByText(/already published/i)
    expect(onPublished).not.toHaveBeenCalled()
  })
})
