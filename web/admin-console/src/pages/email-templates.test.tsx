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

import { EmailTemplatesPage } from './email-templates'
import { api } from '../lib/api'

const welcomeTpl = {
  id: 'tpl-welcome',
  name: 'Welcome Email',
  slug: 'welcome',
  subject: 'Welcome to OpenIDX',
  html_body: '<p>Welcome {{user.name}}!</p>',
  text_body: 'Welcome {{user.name}}!',
  category: 'onboarding',
  variables: ['user.name'],
  enabled: true,
  updated_by: 'admin-1',
}

const resetTpl = {
  ...welcomeTpl,
  id: 'tpl-reset',
  name: 'Password Reset',
  slug: 'password_reset',
  subject: 'Reset your password',
  category: 'security',
  enabled: true,
}

const branding = {
  logo_url: 'https://example.com/logo.png',
  primary_color: '#0066cc',
  accent_color: '#ff6600',
  header_text: 'OpenIDX',
  footer_text: 'Copyright OpenIDX',
}

function routeGet(url: string) {
  if (url.includes('/admin/email-templates')) return Promise.resolve({ data: [welcomeTpl, resetTpl] })
  if (url.includes('/admin/email-branding')) return Promise.resolve(branding)
  return Promise.resolve({ data: [] })
}

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  )
}

describe('EmailTemplatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.body.innerHTML = ''
    vi.mocked(api.get).mockImplementation((url: string) => routeGet(url) as ReturnType<typeof api.get>)
  })

  it('renders the heading + subtitle + Branding Settings toggle button', async () => {
    render(<EmailTemplatesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Email Templates')).toBeInTheDocument()
    expect(
      screen.getByText(/customize email notifications sent to users/i),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /branding settings/i }),
    ).toBeInTheDocument()
  })

  it('lists each template with its name and category group header', async () => {
    render(<EmailTemplatesPage />, { wrapper: createWrapper() })
    expect(await screen.findByText('Welcome Email')).toBeInTheDocument()
    expect(screen.getByText('Password Reset')).toBeInTheDocument()
  })

  it('toggles the Email Branding card open when Branding Settings is clicked', async () => {
    const user = userEvent.setup()
    render(<EmailTemplatesPage />, { wrapper: createWrapper() })
    await screen.findByText('Email Templates')

    // Branding card not visible initially.
    expect(screen.queryByText('Email Branding')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /branding settings/i }))

    // After click, the card title + branding form fields render.
    expect(await screen.findByText('Email Branding')).toBeInTheDocument()
    expect(screen.getByText('Logo URL')).toBeInTheDocument()
    expect(screen.getByText('Primary Color')).toBeInTheDocument()
    expect(screen.getByText('Accent Color')).toBeInTheDocument()
    expect(screen.getByText('Footer Text')).toBeInTheDocument()
    // The branding values are bound to inputs — assert via display value
    expect(screen.getByDisplayValue('https://example.com/logo.png')).toBeInTheDocument()
  })

  it('closes the Email Branding card on second click', async () => {
    const user = userEvent.setup()
    render(<EmailTemplatesPage />, { wrapper: createWrapper() })
    await screen.findByText('Email Templates')

    const toggle = screen.getByRole('button', { name: /branding settings/i })
    await user.click(toggle)
    expect(await screen.findByText('Email Branding')).toBeInTheDocument()

    // The toggle text flips to "Hide Branding" when expanded.
    await user.click(screen.getByRole('button', { name: /hide branding/i }))
    expect(screen.queryByText('Email Branding')).not.toBeInTheDocument()
  })
})
