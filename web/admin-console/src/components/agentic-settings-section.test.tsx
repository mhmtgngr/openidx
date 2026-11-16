import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('../lib/api', () => ({ api: { get: vi.fn(), put: vi.fn() } }))
vi.mock('../hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }))

import { AgenticSettingsSection } from './agentic-settings-section'
import { api } from '../lib/api'

const get = vi.mocked(api.get)
const put = vi.mocked(api.put)

function setup(settings: object, actions: object[] = []) {
  get.mockImplementation((url: string) =>
    Promise.resolve(url.endsWith('/settings') ? settings : { actions }) as never)
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AgenticSettingsSection />
    </QueryClientProvider>,
  )
}

const base = { kill_switch: false, effective_mode: 'observe', provider: 'none', model: '', base_url: '', redaction: 'mask', has_api_key: false }

describe('AgenticSettingsSection', () => {
  beforeEach(() => {
    get.mockReset()
    put.mockReset()
  })

  it('shows the mode, the cap and what was done', async () => {
    setup(
      { ...base, mode: 'tier1', effective_mode: 'observe' },
      [{ id: '1', agent_id: 'pc-1', action: 'restart_tunnel', cause: 'TUNNEL_DOWN', outcome: 'observed', reason: 'observe_mode', created_at: '2026-11-16T12:00:00Z' }],
    )
    expect(await screen.findByLabelText('Mode')).toHaveValue('tier1')
    expect(screen.getByText(/limits automation to "observe"/)).toBeInTheDocument()
    expect(screen.getByText('would do')).toBeInTheDocument()
    expect(screen.getByText('restart the agent')).toBeInTheDocument()
  })

  it('sends only what changed', async () => {
    setup({ ...base, mode: 'observe' })
    put.mockResolvedValue({ ...base, mode: 'observe', kill_switch: true } as never)
    await userEvent.click(await screen.findByLabelText('Stop all automatic fixes now'))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/api/v1/access/agentic/settings', { kill_switch: true }))
    expect(await screen.findByRole('status')).toHaveTextContent('Kill switch is ON')
  })

  it('asks for consent before a cloud model and sends the key once', async () => {
    setup({ ...base, mode: 'observe' })
    put.mockResolvedValue({ ...base, mode: 'observe', provider: 'anthropic', has_api_key: true } as never)
    const user = userEvent.setup()
    await user.selectOptions(await screen.findByLabelText('Model'), 'anthropic')
    const save = screen.getByRole('button', { name: 'Save assistant settings' })
    expect(save).toBeDisabled()
    expect(screen.queryByRole('option', { name: 'Off' })).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('API key'), 'sk-ant-xyz')
    await user.click(screen.getByRole('checkbox', { name: /masked conversation text/ }))
    await user.click(save)
    await waitFor(() => expect(put).toHaveBeenCalledWith('/api/v1/access/agentic/settings', expect.objectContaining({
      provider: 'anthropic', api_key: 'sk-ant-xyz', cloud_consent: true, redaction: 'mask',
    })))
  })
})
