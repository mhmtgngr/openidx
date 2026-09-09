import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    quickLinks: { listMine: vi.fn() },
    pam: { connect: vi.fn() },
  },
}))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { QuickLinksSection } from './quick-links-section'
import { api } from '../lib/api'

const quickLinks = api.quickLinks as unknown as Record<string, ReturnType<typeof vi.fn>>
const pam = api.pam as unknown as Record<string, ReturnType<typeof vi.fn>>

const pamLink = {
  id: 'q1',
  title: 'Prod bastion',
  description: 'Jump host',
  category: 'Infrastructure',
  icon: 'Server',
  type: 'pam' as const,
  pam_entry_id: 'e1',
  pam_renderer: 'guacamole',
  min_role: 'user',
  sort_order: 1,
  enabled: true,
  open_in_new: true,
}

function renderSection() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <QuickLinksSection search="" />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

/**
 * Quick links is the SECOND place a brokered PAM session is launched, and the
 * end-user one — the Connections page is admin-facing. It used to
 * `window.open` the connect URL directly, which the Connections page
 * deliberately does not do: that URL carries a bearer token, and a failed
 * session behind it shows Guacamole's own chrome rather than OpenIDX's. Both
 * launchers now go through the same wrapper, and this file is what keeps this
 * one there — before it, nothing in the suite touched this component at all.
 */
describe('QuickLinksSection', () => {
  beforeEach(() => {
    // Call history must not carry over: "the broker was never asked" is an
    // assertion in this file, and a stale call from the previous test would
    // fail it for the wrong reason.
    vi.clearAllMocks()
    localStorage.clear()
    quickLinks.listMine.mockResolvedValue({ quick_links: [pamLink] })
    pam.connect.mockResolvedValue({
      launch_type: 'guacamole',
      connect_url: 'https://guac/x?token=secret',
      entry_id: 'e1',
    })
    window.open = vi.fn()
  })

  const launch = async () => {
    renderSection()
    fireEvent.click(await screen.findByText('Prod bastion'))
    await waitFor(() => expect(window.open).toHaveBeenCalled())
    return (window.open as ReturnType<typeof vi.fn>).mock.calls[0][0] as string
  }

  it('launches a PAM quick link through the wrapper, never the token-bearing URL', async () => {
    const opened = await launch()
    expect(pam.connect).toHaveBeenCalledWith('e1')
    expect(opened).toMatch(/^\/pam-session\?k=/)
    expect(opened).not.toContain('secret')
    expect(opened).not.toContain('guac')
  })

  it('hands the URL off under the link title, so the window can name the session', async () => {
    const opened = await launch()
    const key = new URLSearchParams(opened.split('?')[1]).get('k')!
    expect(JSON.parse(localStorage.getItem('pam-session:' + key)!)).toMatchObject({
      url: 'https://guac/x?token=secret',
      title: 'Prod bastion',
    })
  })

  it('marks an overlay launch so the window can blame the client, not a fault', async () => {
    pam.connect.mockResolvedValue({
      launch_type: 'guacamole',
      connect_url: 'https://ziti-guac/x?token=secret',
      entry_id: 'e1',
      reach_mode: 'ziti',
    })
    const opened = await launch()
    const key = new URLSearchParams(opened.split('?')[1]).get('k')!
    expect(JSON.parse(localStorage.getItem('pam-session:' + key)!).overlay).toBe(true)
  })

  it('opens an external link directly — no broker, no handoff', async () => {
    quickLinks.listMine.mockResolvedValue({
      quick_links: [{ ...pamLink, id: 'q2', type: 'external', url: 'https://wiki/', pam_entry_id: undefined }],
    })
    renderSection()
    fireEvent.click(await screen.findByText('Prod bastion'))
    await waitFor(() => expect(window.open).toHaveBeenCalledWith('https://wiki/', '_blank', 'noopener'))
    expect(pam.connect).not.toHaveBeenCalled()
  })

  it('hides itself when the user has no quick links', async () => {
    quickLinks.listMine.mockResolvedValue({ quick_links: [] })
    const { container } = renderSection()
    await waitFor(() => expect(container.querySelector('section')).toBeNull())
  })
})
