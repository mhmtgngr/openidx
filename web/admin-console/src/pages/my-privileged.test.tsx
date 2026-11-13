import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import React from 'react'

vi.mock('../lib/api', () => ({ api: { get: vi.fn(), post: vi.fn() } }))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { MyPrivilegedPage } from './my-privileged'
import { MyPrivilegedAccessSection } from '../components/my-privileged-access-section'
import { api } from '../lib/api'

const wrap = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}><MemoryRouter>{children}</MemoryRouter></QueryClientProvider>
  )
}
const conn = (i: number, extra = {}) => ({
  route_id: `r${i}`, name: `srv-${i}`, protocol: 'ssh', hostname: `h${i}`, port: 22,
  require_approval: false, record_session: false, credential_injected: false, ...extra,
})
const mockData = (connections: unknown[], requests: unknown[] = [], checkouts: unknown[] = []) =>
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url.includes('my-connections')) return Promise.resolve({ connections })
    if (url.includes('my-session-requests')) return Promise.resolve({ requests })
    return Promise.resolve({ requests: checkouts })
  })

describe('MyPrivilegedPage', () => {
  beforeEach(() => { vi.clearAllMocks(); localStorage.clear(); vi.spyOn(window, 'open').mockReturnValue(null) })

  it('explains what appears here when empty', async () => {
    mockData([])
    render(<MyPrivilegedPage />, { wrapper: wrap() })
    expect(await screen.findByTestId('my-privileged-empty')).toBeInTheDocument()
    expect(screen.getByText(/remote sessions \(SSH, RDP, VNC\)/)).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'How privileged sessions work' })[0])
      .toHaveAttribute('href', expect.stringContaining('guide/privileged-access'))
  })

  it('lists entries with status lines and shows the notice before connecting', async () => {
    mockData([conn(1, { record_session: true, require_approval: false })],
      [{ id: 'q1', route_id: 'r1', route_name: 'srv-1', protocol: 'ssh', status: 'pending', created_at: '2026-01-01' }],
      [{ id: 'c1', resource_name: 'db-root', resource_type: 'vault_credential', status: 'fulfilled', created_at: '2026-01-01' }])
    vi.mocked(api.post).mockResolvedValue({ connect_url: 'about:blank' })
    render(<MyPrivilegedPage />, { wrapper: wrap() })
    expect(await screen.findAllByText('srv-1')).not.toHaveLength(0)
    expect(screen.getByText('Your screen and keystrokes in this session are recorded.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Launch/ }))
    expect(await screen.findByText('Before you connect to srv-1')).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'I understand, connect' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/v1/access/guacamole/connections/r1/connect'))
    expect(localStorage.getItem('openidx.pamNotice.r1')).toContain('recorded')
  })
})

describe('MyPrivilegedAccessSection compact', () => {
  beforeEach(() => vi.clearAllMocks())
  it('shows at most 3 and links to /my-privileged', async () => {
    mockData([1, 2, 3, 4, 5].map((i) => conn(i)))
    render(<MyPrivilegedAccessSection search="" limit={3} />, { wrapper: wrap() })
    expect(await screen.findByText('srv-3')).toBeInTheDocument()
    expect(screen.queryByText('srv-4')).toBeNull()
    expect(screen.getByTestId('my-privileged-view-all')).toHaveAttribute('href', '/my-privileged')
  })
})
