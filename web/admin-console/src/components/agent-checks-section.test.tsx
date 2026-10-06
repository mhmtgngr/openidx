import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
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

import { AgentChecksSection } from './agent-checks-section'
import { api } from '../lib/api'

// The vocabulary as GET /ziti/posture/check-types serves it (a subset of
// internal/access/posturevocab): the form is built from this, not from a list
// of its own.
const vocabulary = {
  ziti: ['OS', 'Domain', 'MFA', 'Process', 'MAC'],
  agent: [
    { type: 'disk_encryption', platforms: ['windows', 'macos', 'linux', 'android'], params: [] },
    { type: 'os_version', platforms: ['windows', 'macos', 'linux', 'android'], params: [{ name: 'min_version', kind: 'version' }] },
    { type: 'patch_level', platforms: ['windows', 'macos', 'linux', 'android'], params: [{ name: 'max_days', kind: 'integer', min: 1, max: 3650 }] },
    { type: 'play_integrity', platforms: ['android'], params: [{ name: 'require_play_recognized', kind: 'boolean' }] },
    { type: 'process_running', platforms: ['linux'], params: [{ name: 'processes', kind: 'string_list', required: true, max: 64 }] },
  ],
  severities: ['low', 'medium', 'high', 'critical'],
  platforms: ['windows', 'macos', 'linux', 'android', 'ios'],
}

const osCheck = {
  id: 'chk-1',
  name: 'Windows 10 22H2 or later',
  check_type: 'os_version',
  parameters: { min_version: '10.0.19045' },
  enabled: true,
  severity: 'high',
  platforms: ['windows'],
  kind: 'agent',
}

function routeGet(checks: unknown[]) {
  return (url: string) => {
    if (url.includes('/ziti/posture/check-types')) return Promise.resolve(vocabulary)
    if (url.includes('/ziti/posture/checks')) return Promise.resolve(checks)
    return Promise.resolve([])
  }
}

function renderSection() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter><AgentChecksSection /></MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AgentChecksSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation(routeGet([osCheck]) as typeof api.get)
  })

  it('lists only the agent checks, with their type, severity, platforms and settings', async () => {
    renderSection()
    expect(await screen.findByText('Windows 10 22H2 or later')).toBeInTheDocument()
    // The list asks the server for the agent kind only.
    expect(api.get).toHaveBeenCalledWith('/api/v1/access/ziti/posture/checks?kind=agent')
    const row = screen.getByText('Windows 10 22H2 or later').closest('tr')!
    expect(within(row).getByText('OS version')).toBeInTheDocument()
    expect(within(row).getByText('High')).toBeInTheDocument()
    expect(within(row).getByText('Windows')).toBeInTheDocument()
    expect(within(row).getByText('min_version: 10.0.19045')).toBeInTheDocument()
  })

  it('says what an empty list means', async () => {
    vi.mocked(api.get).mockImplementation(routeGet([]) as typeof api.get)
    renderSection()
    expect(await screen.findByText(/no agent checks are configured/i)).toBeInTheDocument()
  })

  it('creates a check from the form the type describes', async () => {
    const user = userEvent.setup()
    renderSection()
    await screen.findByText('Windows 10 22H2 or later')

    await user.click(screen.getByRole('button', { name: /add check/i }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Name'), 'Patched within two weeks')
    await user.selectOptions(within(dialog).getByLabelText('Check'), 'patch_level')
    await user.type(within(dialog).getByLabelText('Maximum days since last update'), '14')
    await user.selectOptions(within(dialog).getByLabelText('Severity'), 'critical')
    await user.click(within(dialog).getByLabelText('Windows'))
    await user.click(within(dialog).getByRole('button', { name: /add check/i }))

    expect(api.post).toHaveBeenCalledWith('/api/v1/access/ziti/posture/checks', {
      name: 'Patched within two weeks',
      check_type: 'patch_level',
      severity: 'critical',
      enabled: true,
      platforms: ['windows'],
      parameters: { max_days: 14 },
    })
  })

  it('offers only the platforms and settings the chosen type has', async () => {
    const user = userEvent.setup()
    renderSection()
    await screen.findByText('Windows 10 22H2 or later')

    await user.click(screen.getByRole('button', { name: /add check/i }))
    const dialog = await screen.findByRole('dialog')
    await user.selectOptions(within(dialog).getByLabelText('Check'), 'process_running')

    // process_running reads /proc, so Linux is the only platform it runs on.
    expect(within(dialog).getByLabelText('Linux')).toBeInTheDocument()
    expect(within(dialog).queryByLabelText('Windows')).not.toBeInTheDocument()
    expect(within(dialog).queryByLabelText('Minimum version')).not.toBeInTheDocument()

    await user.type(within(dialog).getByLabelText('Name'), 'Audit daemon')
    await user.type(within(dialog).getByLabelText(/^processes/i), 'auditd{enter}sshd')
    await user.click(within(dialog).getByRole('button', { name: /add check/i }))

    expect(api.post).toHaveBeenCalledWith('/api/v1/access/ziti/posture/checks', expect.objectContaining({
      check_type: 'process_running',
      platforms: [],
      parameters: { processes: ['auditd', 'sshd'] },
    }))
  })

  it('drops a platform the new type cannot run on when the type changes', async () => {
    const user = userEvent.setup()
    renderSection()
    await screen.findByText('Windows 10 22H2 or later')

    await user.click(screen.getByRole('button', { name: /add check/i }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Name'), 'Integrity')
    await user.click(within(dialog).getByLabelText('Windows'))
    await user.click(within(dialog).getByLabelText('Android'))
    await user.selectOptions(within(dialog).getByLabelText('Check'), 'play_integrity')
    await user.click(within(dialog).getByLabelText(/recognised by play/i))
    await user.click(within(dialog).getByRole('button', { name: /add check/i }))

    expect(api.post).toHaveBeenCalledWith('/api/v1/access/ziti/posture/checks', expect.objectContaining({
      check_type: 'play_integrity',
      platforms: ['android'],
      parameters: { require_play_recognized: true },
    }))
  })

  it('edits a check with its stored settings filled in', async () => {
    const user = userEvent.setup()
    renderSection()
    await screen.findByText('Windows 10 22H2 or later')

    await user.click(screen.getByRole('button', { name: 'Edit Windows 10 22H2 or later' }))
    const dialog = await screen.findByRole('dialog')
    const minVersion = within(dialog).getByLabelText('Minimum version')
    expect(minVersion).toHaveValue('10.0.19045')
    expect(within(dialog).getByLabelText('Windows')).toBeChecked()

    await user.clear(minVersion)
    await user.type(minVersion, '10.0.22631')
    await user.click(within(dialog).getByRole('switch', { name: 'Enabled' }))
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))

    expect(api.put).toHaveBeenCalledWith('/api/v1/access/ziti/posture/checks/chk-1', {
      name: 'Windows 10 22H2 or later',
      check_type: 'os_version',
      severity: 'high',
      enabled: false,
      platforms: ['windows'],
      parameters: { min_version: '10.0.22631' },
    })
  })

  it('leaves an empty optional setting out so the agent uses its default', async () => {
    const user = userEvent.setup()
    renderSection()
    await screen.findByText('Windows 10 22H2 or later')

    await user.click(screen.getByRole('button', { name: /add check/i }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Name'), 'Any recent OS')
    await user.selectOptions(within(dialog).getByLabelText('Check'), 'os_version')
    await user.click(within(dialog).getByRole('button', { name: /add check/i }))

    expect(api.post).toHaveBeenCalledWith('/api/v1/access/ziti/posture/checks', expect.objectContaining({
      check_type: 'os_version',
      parameters: {},
    }))
  })

  it('shows the reason the server gave for refusing a check', async () => {
    const user = userEvent.setup()
    vi.mocked(api.post).mockRejectedValueOnce({
      response: {
        status: 400,
        data: {
          error: 'min_version must be a version made of numbers and dots, such as 10.0.19045',
          code: 'invalid_param',
          field: 'parameters.min_version',
        },
      },
    })
    renderSection()
    await screen.findByText('Windows 10 22H2 or later')

    await user.click(screen.getByRole('button', { name: /add check/i }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Name'), 'Bad version')
    await user.selectOptions(within(dialog).getByLabelText('Check'), 'os_version')
    await user.type(within(dialog).getByLabelText('Minimum version'), 'v10')
    await user.click(within(dialog).getByRole('button', { name: /add check/i }))

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(/numbers and dots/)
    // The dialog stays open so the value can be corrected.
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('deletes a check only after confirmation', async () => {
    const user = userEvent.setup()
    renderSection()
    await screen.findByText('Windows 10 22H2 or later')

    await user.click(screen.getByRole('button', { name: 'Delete Windows 10 22H2 or later' }))
    const confirm = await screen.findByRole('alertdialog')
    expect(api.delete).not.toHaveBeenCalled()
    await user.click(within(confirm).getByRole('button', { name: 'Delete' }))
    expect(api.delete).toHaveBeenCalledWith('/api/v1/access/ziti/posture/checks/chk-1')
  })

  it('reports a list the caller may not read instead of an empty one', async () => {
    vi.mocked(api.get).mockImplementation(((url: string) => {
      if (url.includes('/check-types')) return Promise.resolve(vocabulary)
      return Promise.reject({ response: { status: 403, data: { error: 'operator access required' } } })
    }) as typeof api.get)
    renderSection()
    expect(await screen.findByText(/permission/i)).toBeInTheDocument()
    expect(screen.queryByText(/no agent checks are configured/i)).not.toBeInTheDocument()
  })
})
