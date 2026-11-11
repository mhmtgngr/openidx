import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

import { AddRouterDialog, SiteSelect } from './site-select'
import { api } from '../lib/api'

const sites = {
  sites: [
    { id: 's0', slug: 'default', name: 'Default site', description: '', hop_addr: '', is_default: true, routers: 1 },
    { id: 's1', slug: 'azure', name: 'Azure', description: '', hop_addr: '', is_default: false, routers: 0 },
  ],
}

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

beforeEach(() => {
  vi.mocked(api.get).mockReset()
  vi.mocked(api.post).mockReset()
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url === '/api/v1/access/sites') return Promise.resolve(sites)
    return Promise.resolve({ id: 'er-1', isOnline: false, isVerified: false })
  })
})

describe('SiteSelect', () => {
  it('lists the sites and reports the default as empty', async () => {
    const onChange = vi.fn()
    wrap(<SiteSelect id="s" value="azure" onChange={onChange} />)
    await screen.findByRole('option', { name: 'Azure (azure)' })
    await userEvent.selectOptions(screen.getByLabelText('Site'), 'default')
    expect(onChange).toHaveBeenCalledWith('')
  })
})

describe('AddRouterDialog', () => {
  it('creates a site, enrolls the router into it and shows the command', async () => {
    vi.mocked(api.post).mockImplementation((url: string) => {
      if (url === '/api/v1/access/sites') return Promise.resolve({ ...sites.sites[1], id: 's2', slug: 'branch' })
      return Promise.resolve({
        router_id: 'er-1', name: 'r1', site_slug: 'branch', image_tag: '1.6.12', enrollment_jwt: 'j',
        controller: 'ctrl:1280', onboard_command: 'docker run ... openziti/ziti-router:1.6.12',
      })
    })
    wrap(<AddRouterDialog open onOpenChange={() => {}} />)
    await screen.findByRole('option', { name: 'Azure (azure)' })
    await userEvent.selectOptions(screen.getByLabelText('Site'), '__new__')
    await userEvent.type(screen.getByLabelText('Site slug'), 'branch')
    await userEvent.type(screen.getByLabelText('Advertised address'), 'router.branch.example')
    await userEvent.click(screen.getByRole('button', { name: /Create router/ }))
    expect(await screen.findByTestId('onboard-command')).toHaveTextContent('openziti/ziti-router:1.6.12')
    expect(api.post).toHaveBeenCalledWith('/api/v1/access/sites', { slug: 'branch', name: undefined })
    expect(api.post).toHaveBeenCalledWith('/api/v1/access/ziti/fabric/routers/enroll-token', {
      name: undefined, site_slug: 'branch', advertised_address: 'router.branch.example',
    })
    await waitFor(() => expect(screen.getByText('Waiting for the router')).toBeInTheDocument())
  })

  it('refuses a missing address before calling the API', async () => {
    wrap(<AddRouterDialog open onOpenChange={() => {}} />)
    await userEvent.click(screen.getByRole('button', { name: /Create router/ }))
    expect(screen.getByRole('alert')).toHaveTextContent('advertised address is required')
    expect(api.post).not.toHaveBeenCalled()
  })
})
