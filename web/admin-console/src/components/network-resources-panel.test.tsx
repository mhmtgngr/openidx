import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(() => Promise.resolve({})),
    post: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

vi.mock('../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}))

import { NetworkResourcesPanel } from './network-resources-panel'
import { draftFromTarget, targetFromDraft, formatPorts, EMPTY_DRAFT } from '../lib/network-target'
import { api } from '../lib/api'

function wrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  )
}

const resource = {
  id: 'app-1',
  name: 'File servers',
  description: '',
  enabled: true,
  service_name: 'openidx-net-app-1',
  sync_status: 'synced',
  target: {
    hosts: ['fs1.corp.example'],
    cidrs: ['10.0.0.0/16'],
    dns_names: [],
    port_ranges: [{ low: 445, high: 445 }],
    protocols: ['tcp'],
  },
}

describe('network target draft', () => {
  it('turns the form into a target', () => {
    const { target, error } = targetFromDraft({
      ...EMPTY_DRAFT,
      hosts: 'fs1.corp.example, fs2.corp.example',
      cidrs: '10.0.0.0/16\n192.168.0.0/16',
      ports: '445, 8000-8100',
      udp: false,
    })
    expect(error).toBeUndefined()
    expect(target).toEqual({
      hosts: ['fs1.corp.example', 'fs2.corp.example'],
      cidrs: ['10.0.0.0/16', '192.168.0.0/16'],
      dns_names: [],
      port_ranges: [{ low: 445, high: 445 }, { low: 8000, high: 8100 }],
      protocols: ['tcp'],
      forward_address: undefined,
      forward_port: undefined,
    })
  })

  it('refuses what a typo makes obvious', () => {
    expect(targetFromDraft(EMPTY_DRAFT).error).toBe('needAddress')
    expect(targetFromDraft({ ...EMPTY_DRAFT, hosts: 'a', ports: '70000' }).error).toBe('badPort')
    expect(targetFromDraft({ ...EMPTY_DRAFT, hosts: 'a', ports: '90-80' }).error).toBe('badPort')
    expect(targetFromDraft({ ...EMPTY_DRAFT, hosts: 'a', tcp: false, udp: false }).error).toBe('needProtocol')
    expect(targetFromDraft({ ...EMPTY_DRAFT, hosts: 'a', forward_port: '0' }).error).toBe('badPort')
  })

  it('round-trips a stored target, with every port shown as empty', () => {
    expect(formatPorts([{ low: 1, high: 65535 }])).toBe('')
    const d = draftFromTarget(resource.target)
    expect(d.ports).toBe('445')
    expect(d.tcp).toBe(true)
    expect(d.udp).toBe(false)
    expect(targetFromDraft(d).target?.cidrs).toEqual(['10.0.0.0/16'])
  })
})

describe('NetworkResourcesPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.endsWith('/network-resources')) return Promise.resolve({ resources: [resource], total: 1 })
      if (url.endsWith('/network-policy')) {
        return Promise.resolve({ always_on: false, split_tunnel: true, block_direct_corporate_cidrs: false })
      }
      return Promise.resolve([])
    })
  })

  it('lists the resources with what they cover and the network policy', async () => {
    render(<NetworkResourcesPanel />, { wrapper: wrapper() })
    expect(await screen.findByText('File servers')).toBeInTheDocument()
    expect(screen.getByText('fs1.corp.example, 10.0.0.0/16')).toBeInTheDocument()
    expect(screen.getByText('445 · TCP')).toBeInTheDocument()
    expect(screen.getByText('Synced')).toBeInTheDocument()
    expect(await screen.findByText('Network policy')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('switch', { name: 'Split tunnel' })).toBeChecked())
    expect(screen.getByRole('switch', { name: 'Always on' })).not.toBeChecked()
  })

  it('creates a resource with its network target', async () => {
    render(<NetworkResourcesPanel />, { wrapper: wrapper() })
    fireEvent.click(await screen.findByRole('button', { name: /Add network resource/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Lab' } })
    fireEvent.change(screen.getByLabelText('CIDRs'), { target: { value: '172.16.0.0/16' } })
    fireEvent.change(screen.getByLabelText('Ports'), { target: { value: '22' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.post).toHaveBeenCalled())
    const [url, body] = vi.mocked(api.post).mock.calls[0]
    expect(url).toBe('/api/v1/access/network-resources')
    expect(body).toMatchObject({
      name: 'Lab',
      target: { cidrs: ['172.16.0.0/16'], port_ranges: [{ low: 22, high: 22 }], protocols: ['tcp', 'udp'] },
    })
  })

  it('says what is wrong instead of saving a target with no address', async () => {
    render(<NetworkResourcesPanel />, { wrapper: wrapper() })
    fireEvent.click(await screen.findByRole('button', { name: /Add network resource/ }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Empty' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('at least one host')
    expect(api.post).not.toHaveBeenCalled()
  })

  it('saves an edited target with PUT', async () => {
    render(<NetworkResourcesPanel />, { wrapper: wrapper() })
    fireEvent.click(await screen.findByRole('button', { name: 'Edit target' }))
    fireEvent.change(screen.getByLabelText('Ports'), { target: { value: '445, 139' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.put).toHaveBeenCalled())
    const [url, body] = vi.mocked(api.put).mock.calls[0]
    expect(url).toBe('/api/v1/access/resources/app-1/network-target')
    expect(body).toMatchObject({ port_ranges: [{ low: 445, high: 445 }, { low: 139, high: 139 }] })
  })

  it('changes the network policy one switch at a time', async () => {
    vi.mocked(api.put).mockResolvedValue({ always_on: true, split_tunnel: true, block_direct_corporate_cidrs: false })
    render(<NetworkResourcesPanel />, { wrapper: wrapper() })
    const always = await screen.findByRole('switch', { name: 'Always on' })
    fireEvent.click(always)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/access/network-policy', { always_on: true }),
    )
  })
})
