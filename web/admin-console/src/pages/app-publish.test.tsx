import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
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

import { AppPublishPage } from './app-publish'
import { api } from '../lib/api'

const discoveredApp = {
  id: 'app-1',
  name: 'HR Portal',
  description: 'Employee management system',
  target_url: 'http://hr.internal:8080',
  spec_url: 'http://hr.internal:8080/openapi.json',
  status: 'discovered',
  discovery_started_at: '2026-06-09T10:00:00Z',
  discovery_completed_at: '2026-06-09T10:05:00Z',
  discovery_error: null,
  discovery_strategies: ['openapi', 'crawl'],
  total_paths_discovered: 18,
  total_paths_published: 5,
  created_at: '2026-06-09T09:00:00Z',
  updated_at: '2026-06-09T10:05:00Z',
}

const erroredApp = {
  ...discoveredApp,
  id: 'app-2',
  name: 'Finance API',
  target_url: 'http://finance.internal:9000',
  status: 'error',
  discovery_error: 'spec_url unreachable',
  discovery_strategies: ['openapi'],
  total_paths_discovered: 0,
  total_paths_published: 0,
}

function routeGet(url: string) {
  if (url.endsWith('/access/apps')) {
    return Promise.resolve({ apps: [discoveredApp, erroredApp], total: 2 })
  }
  if (url.includes('/paths')) return Promise.resolve({ paths: [], total: 0 })
  if (url.includes('/access/apps/')) return Promise.resolve(discoveredApp)
  return Promise.resolve({ apps: [], total: 0 })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('AppPublishPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle', async () => {
    render(<AppPublishPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('App Publish')).toBeInTheDocument()
    expect(
      screen.getByText(/register internal apps, discover endpoints, classify security levels, and publish as proxy routes/i),
    ).toBeInTheDocument()
  })

  it('shows all three tabs, with Paths and Published disabled until an app is selected', async () => {
    render(<AppPublishPage />, { wrapper: createWrapper() })
    // Wait for the Apps tab count to update so the queries have settled.
    expect(await screen.findByRole('tab', { name: /apps \(2\)/i })).toBeInTheDocument()

    // No selected app yet — Paths and Published tabs render in disabled state.
    const pathsTab = screen.getByRole('tab', { name: /^discovered paths/i })
    expect(pathsTab).toHaveAttribute('data-state', 'inactive')
    expect(pathsTab).toBeDisabled()

    const publishedTab = screen.getByRole('tab', { name: /^published/i })
    expect(publishedTab).toBeDisabled()
  })

  it('lists each registered app with name, target URL, status badge, and discovery counts', async () => {
    render(<AppPublishPage />, { wrapper: createWrapper() })
    // Names + target URLs from the fixture
    expect(await screen.findByText('HR Portal')).toBeInTheDocument()
    expect(screen.getByText('http://hr.internal:8080')).toBeInTheDocument()
    expect(screen.getByText('Finance API')).toBeInTheDocument()
    expect(screen.getByText('http://finance.internal:9000')).toBeInTheDocument()

    // Status badges
    expect(screen.getByText('discovered')).toBeInTheDocument()
    expect(screen.getByText('error')).toBeInTheDocument()

    // Discovery counts on the HR Portal card
    expect(screen.getByText('18 discovered')).toBeInTheDocument()
    expect(screen.getByText('5 published')).toBeInTheDocument()

    // Discovery strategies — "openapi" appears on both apps' cards, so
    // assert it's present at least once and that "crawl" (HR-only)
    // surfaces too.
    expect(screen.getAllByText('openapi').length).toBeGreaterThan(0)
    expect(screen.getByText('crawl')).toBeInTheDocument()
  })

  it('surfaces the discovery_error on the errored app card', async () => {
    render(<AppPublishPage />, { wrapper: createWrapper() })
    await screen.findByText('Finance API')
    expect(screen.getByText('spec_url unreachable')).toBeInTheDocument()
  })

  it('opens the Register App dialog when the Register App button is clicked', async () => {
    const user = userEvent.setup()
    render(<AppPublishPage />, { wrapper: createWrapper() })
    await screen.findByText('App Publish')

    await user.click(screen.getByRole('button', { name: /register app/i }))
    // The dialog body has a stable name placeholder; anchor on it rather
    // than the dialog title (which duplicates the trigger).
    expect(
      await screen.findByPlaceholderText(/my internal app/i),
    ).toBeInTheDocument()
    // The other form-field placeholders all render too.
    expect(screen.getByPlaceholderText('http://internal-app:8080')).toBeInTheDocument()
  })

  it('renders the empty state when no apps are registered', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.endsWith('/access/apps')) {
        return Promise.resolve({ apps: [], total: 0 }) as ReturnType<typeof api.get>
      }
      return routeGet(url) as ReturnType<typeof api.get>
    })
    render(<AppPublishPage />, { wrapper: createWrapper() })

    expect(
      await screen.findByText(/no apps registered yet/i),
    ).toBeInTheDocument()
  })
})
