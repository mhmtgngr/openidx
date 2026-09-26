import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the API module
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(() => Promise.resolve([])),
    getWithHeaders: vi.fn(() => Promise.resolve({ data: [], headers: {} })),
    post: vi.fn(() => Promise.resolve({})),
    put: vi.fn(() => Promise.resolve({})),
    delete: vi.fn(() => Promise.resolve({})),
  },
}))

// Import after mocks
import { ApplicationsPage } from '../pages/applications'
import { api } from '../lib/api'

const mockApplications = [
  {
    id: '1',
    name: 'Test App',
    description: 'A test application',
    client_id: 'test-client-id',
    created_at: '2024-01-01T00:00:00Z',
    enabled: true,
  },
]

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })

  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('ApplicationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''

    vi.mocked(api.get).mockResolvedValue(mockApplications)
    vi.mocked(api.getWithHeaders).mockResolvedValue({ data: mockApplications, headers: {} })
  })

  it('renders the applications page heading', async () => {
    const wrapper = createWrapper()

    render(<ApplicationsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Applications')).toBeInTheDocument()
    })
  })

  it('displays application list', async () => {
    const wrapper = createWrapper()

    render(<ApplicationsPage />, { wrapper })

    await waitFor(() => {
      expect(screen.getByText('Test App')).toBeInTheDocument()
    })
  })

  it('has add application button', async () => {
    const wrapper = createWrapper()

    render(<ApplicationsPage />, { wrapper })

    await waitFor(() => {
      const addButton = screen.queryByRole('button', { name: /register application/i })
      expect(addButton).toBeInTheDocument()
    })
  })

  // The edit dialog's "Require PKCE" box and the back-channel logout URI come
  // from, and go to, the backing OAuth client. Until this block existed the
  // box showed its default for every application (the API never returned
  // pkce_required) and the URI had no field at all.
  describe('edit dialog OAuth client settings', () => {
    const oidcApp = {
      id: 'app-1',
      client_id: 'grafana',
      name: 'Grafana',
      description: 'Dashboards',
      type: 'web',
      protocol: 'oidc',
      base_url: 'https://grafana.example',
      redirect_uris: ['https://grafana.example/cb'],
      enabled: true,
      pkce_required: false,
      back_channel_logout_uri: 'https://grafana.example/bcl',
      post_logout_redirect_uris: ['https://grafana.example/bye'],
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    }

    const openEditDialog = async () => {
      const user = userEvent.setup()
      vi.mocked(api.getWithHeaders).mockResolvedValue({ data: [oidcApp], headers: {} })
      render(<ApplicationsPage />, { wrapper: createWrapper() })
      await screen.findByText('Grafana')
      // The row menu trigger is the icon-only button carrying aria-haspopup.
      const triggers = screen.getAllByRole('button').filter((b) => b.getAttribute('aria-haspopup') === 'menu')
      expect(triggers.length).toBeGreaterThan(0)
      await user.click(triggers[0])
      const edit = await screen.findByRole('menuitem', { name: /edit application/i })
      await user.click(edit)
      await screen.findByLabelText(/back-channel logout uri/i)
      return user
    }

    it('shows the application\'s own PKCE setting and logout URI, not defaults', async () => {
      await openEditDialog()
      expect((screen.getByLabelText(/require pkce/i) as HTMLInputElement).checked).toBe(false)
      expect((screen.getByLabelText(/back-channel logout uri/i) as HTMLInputElement).value).toBe('https://grafana.example/bcl')
    })

    it('saves both settings to the application', async () => {
      const user = await openEditDialog()
      await user.click(screen.getByLabelText(/require pkce/i))
      const uri = screen.getByLabelText(/back-channel logout uri/i)
      await user.clear(uri)
      await user.type(uri, 'https://grafana.example/bcl-v2')
      await user.click(screen.getByRole('button', { name: /update application/i }))

      await waitFor(() => expect(api.put).toHaveBeenCalled())
      const [url, data] = vi.mocked(api.put).mock.calls[0]
      expect(String(url)).toBe('/api/v1/applications/app-1')
      expect(data).toMatchObject({
        pkce_required: true,
        back_channel_logout_uri: 'https://grafana.example/bcl-v2',
      })
    })

    // The OAuth service falls back to matching a logout redirect by ORIGIN
    // against the application's redirect URIs, and logs advice to register
    // post_logout_redirect_uris instead. Until this field existed that advice
    // could only be taken through dynamic client registration, so every
    // console-managed installation stayed on the loose rule for good.
    it("shows the application's registered post-logout URIs", async () => {
      await openEditDialog()
      const box = screen.getByLabelText(/post-logout redirect uris/i) as HTMLTextAreaElement
      expect(box.value).toBe('https://grafana.example/bye')
    })

    it('saves the post-logout allowlist as a list, one entry per line', async () => {
      const user = await openEditDialog()
      const box = screen.getByLabelText(/post-logout redirect uris/i)
      await user.clear(box)
      await user.type(box, 'https://grafana.example/bye{enter}https://grafana.example/signed-out')
      await user.click(screen.getByRole('button', { name: /update application/i }))

      await waitFor(() => expect(api.put).toHaveBeenCalled())
      const [, data] = vi.mocked(api.put).mock.calls[0]
      expect(data).toMatchObject({
        post_logout_redirect_uris: ['https://grafana.example/bye', 'https://grafana.example/signed-out'],
      })
    })

    // Clearing the box is how an operator deliberately goes back to the origin
    // fallback, so it has to travel as an empty list rather than as an omitted
    // key: the server leaves the column alone when the key is absent.
    it('sends an empty list when the box is cleared', async () => {
      const user = await openEditDialog()
      await user.clear(screen.getByLabelText(/post-logout redirect uris/i))
      await user.click(screen.getByRole('button', { name: /update application/i }))

      await waitFor(() => expect(api.put).toHaveBeenCalled())
      const [, data] = vi.mocked(api.put).mock.calls[0]
      expect((data as Record<string, unknown>).post_logout_redirect_uris).toEqual([])
    })
  })

  // Whether an application's access tokens may call OpenIDX's own APIs is a
  // setting of its OAuth client: shown in the list so an operator can review
  // which applications have it, and edited and registered like the settings
  // above.
  describe('OpenIDX API access', () => {
    const app = (overrides: Record<string, unknown>) => ({
      id: 'app-1',
      client_id: 'grafana',
      name: 'Grafana',
      description: 'Dashboards',
      type: 'web',
      protocol: 'oidc',
      base_url: 'https://grafana.example',
      redirect_uris: ['https://grafana.example/cb'],
      enabled: true,
      pkce_required: true,
      post_logout_redirect_uris: [],
      api_access: false,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
      ...overrides,
    })

    const openEditDialogFor = async (application: Record<string, unknown>) => {
      const user = userEvent.setup()
      vi.mocked(api.getWithHeaders).mockResolvedValue({ data: [application], headers: {} })
      render(<ApplicationsPage />, { wrapper: createWrapper() })
      await screen.findByText(application.name as string)
      const triggers = screen.getAllByRole('button').filter((b) => b.getAttribute('aria-haspopup') === 'menu')
      await user.click(triggers[0])
      await user.click(await screen.findByRole('menuitem', { name: /edit application/i }))
      await screen.findByRole('button', { name: /update application/i })
      return user
    }

    it('marks the applications that may call the OpenIDX API in the list', async () => {
      vi.mocked(api.getWithHeaders).mockResolvedValue({
        data: [app({ id: 'a', name: 'Console', api_access: true }), app({ id: 'b', name: 'Wiki', client_id: 'wiki' })],
        headers: {},
      })
      render(<ApplicationsPage />, { wrapper: createWrapper() })
      await screen.findByText('Wiki')
      expect(screen.getAllByText('OpenIDX API')).toHaveLength(1)
      const consoleRow = screen.getByText('Console').closest('tr') as HTMLElement
      expect(consoleRow).toHaveTextContent('OpenIDX API')
    })

    it("shows the application's setting and saves the change", async () => {
      const user = await openEditDialogFor(app({ api_access: false }))
      const box = screen.getByLabelText(/may call the openidx api/i) as HTMLInputElement
      expect(box.checked).toBe(false)
      await user.click(box)
      await user.click(screen.getByRole('button', { name: /update application/i }))

      await waitFor(() => expect(api.put).toHaveBeenCalled())
      const [url, data] = vi.mocked(api.put).mock.calls[0]
      expect(String(url)).toBe('/api/v1/applications/app-1')
      expect(data).toMatchObject({ api_access: true })
    })

    it('saves turning it off', async () => {
      const user = await openEditDialogFor(app({ api_access: true }))
      const box = screen.getByLabelText(/may call the openidx api/i) as HTMLInputElement
      expect(box.checked).toBe(true)
      await user.click(box)
      await user.click(screen.getByRole('button', { name: /update application/i }))

      await waitFor(() => expect(api.put).toHaveBeenCalled())
      expect(vi.mocked(api.put).mock.calls[0][1]).toMatchObject({ api_access: false })
    })

    // A tile with no OAuth client behind it has no such setting: no box, and
    // nothing sent that the server would have nowhere to write.
    it('offers no setting for a tile with no OAuth client', async () => {
      const tile = app({ client_id: 'proxy-app-route-1', name: 'Intranet' })
      delete (tile as Record<string, unknown>).api_access
      const user = await openEditDialogFor(tile)
      expect(screen.queryByLabelText(/may call the openidx api/i)).not.toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: /update application/i }))

      await waitFor(() => expect(api.put).toHaveBeenCalled())
      expect(vi.mocked(api.put).mock.calls[0][1]).not.toHaveProperty('api_access')
    })

    it("warns before the console's own application loses it", async () => {
      const user = await openEditDialogFor(app({ client_id: 'admin-console', name: 'Admin Console', api_access: true }))
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      await user.click(screen.getByLabelText(/may call the openidx api/i))
      expect(screen.getByRole('alert')).toHaveTextContent(/console itself signs in with/i)
    })

    it('registers an application without it unless it is ticked', async () => {
      const user = userEvent.setup()
      render(<ApplicationsPage />, { wrapper: createWrapper() })
      await user.click(await screen.findByRole('button', { name: /register application/i }))
      await user.type(await screen.findByLabelText(/application name/i), 'Wiki')
      await user.type(screen.getByLabelText(/^redirect uris/i), 'https://wiki.example/cb')
      expect((screen.getByLabelText(/may call the openidx api/i) as HTMLInputElement).checked).toBe(false)
      // The page's own button opens the dialog; the dialog's submits it.
      const register = screen.getAllByRole('button', { name: /register application/i })
      await user.click(register[register.length - 1])

      await waitFor(() => expect(api.post).toHaveBeenCalled())
      const [url, data] = vi.mocked(api.post).mock.calls[0]
      expect(String(url)).toBe('/api/v1/oauth/clients')
      expect(data).toMatchObject({ name: 'Wiki', api_access: false })
    })

    it('registers an application with it when it is ticked', async () => {
      const user = userEvent.setup()
      render(<ApplicationsPage />, { wrapper: createWrapper() })
      await user.click(await screen.findByRole('button', { name: /register application/i }))
      await user.type(await screen.findByLabelText(/application name/i), 'Desktop')
      await user.type(screen.getByLabelText(/^redirect uris/i), 'http://127.0.0.1:47600/callback')
      await user.click(screen.getByLabelText(/may call the openidx api/i))
      // The page's own button opens the dialog; the dialog's submits it.
      const register = screen.getAllByRole('button', { name: /register application/i })
      await user.click(register[register.length - 1])

      await waitFor(() => expect(api.post).toHaveBeenCalled())
      expect(vi.mocked(api.post).mock.calls[0][1]).toMatchObject({ name: 'Desktop', api_access: true })
    })
  })
})
