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
  if (url.includes('/email-templates')) return Promise.resolve({ data: [welcomeTpl, resetTpl] })
  if (url.includes('/email-branding')) return Promise.resolve(branding)
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

  // The preview shows HTML one administrator wrote to the others who open it,
  // platform admins among them. It has to look as the email will, and none of
  // it may become part of the console's document, where it would run with the
  // console's origin and could read the tokens the console keeps.
  describe('preview', () => {
    const planted =
      '<h1 id="planted-heading">Welcome, John!</h1>' +
      '<img id="planted-img" src="x" onerror="window.__planted = true">' +
      '<script id="planted-script">window.__planted = true</script>'

    async function openPreview() {
      const user = userEvent.setup()
      vi.mocked(api.post).mockImplementationOnce(
        () => Promise.resolve({ html: planted }) as ReturnType<typeof api.post>,
      )
      render(<EmailTemplatesPage />, { wrapper: createWrapper() })
      await user.click(await screen.findByText('Welcome Email'))
      await user.click(screen.getByRole('button', { name: /^preview$/i }))
      return screen.findByTitle('Email preview')
    }

    it('shows the rendered template in a frame that grants it nothing', async () => {
      const frame = await openPreview()

      expect(api.post).toHaveBeenCalledWith('/api/v1/email-templates/tpl-welcome/preview', {})
      expect(frame.tagName).toBe('IFRAME')
      // The administrator sees exactly what the server rendered...
      expect(frame.getAttribute('srcdoc')).toBe(planted)
      // ...in a sandbox with no allowances: without allow-scripts nothing in it
      // runs, and without allow-same-origin its origin is not the console's.
      const sandbox = frame.getAttribute('sandbox')
      expect(sandbox).not.toBeNull()
      expect(sandbox!.split(/\s+/).filter(Boolean)).toEqual([])
    })

    it('never places the template markup in the console document', async () => {
      await openPreview()

      expect(document.getElementById('planted-heading')).toBeNull()
      expect(document.getElementById('planted-img')).toBeNull()
      expect(document.getElementById('planted-script')).toBeNull()
      expect(document.querySelector('[onerror]')).toBeNull()
    })
  })
})
