import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

// SwaggerUI pulls in a giant module that can't render in jsdom/happy-dom —
// stub it to a simple element.
vi.mock('swagger-ui-react', () => ({
  default: ({ url }: { url: string }) => (
    <div data-testid="swagger-ui">SwaggerUI({url})</div>
  ),
}))

vi.mock('swagger-ui-react/swagger-ui.css', () => ({}))
vi.mock('../styles/swagger-overrides.css', () => ({}))

import { ApiDocsPage } from './api-docs'
import { API_SPECS } from '@/lib/api-specs'
import en from '@/i18n/locales/en'

describe('ApiDocsPage', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
  })

  it('renders the heading + the Interactive API Reference card', () => {
    render(
      <MemoryRouter>
        <ApiDocsPage />
      </MemoryRouter>,
    )

    expect(screen.getByText('API Documentation')).toBeInTheDocument()
    expect(screen.getByText('Interactive API Reference')).toBeInTheDocument()
    expect(
      screen.getByText(
        /explore and test openidx apis\. your authentication token is automatically included/i,
      ),
    ).toBeInTheDocument()
  })

  it('exposes one tab per API spec', () => {
    render(
      <MemoryRouter>
        <ApiDocsPage />
      </MemoryRouter>,
    )

    // The list comes from the page's own API_SPECS and the label from the
    // English catalog, so retiring a spec cannot leave a phantom tab asserted
    // here — or a real one unasserted.
    expect(API_SPECS.length).toBeGreaterThan(0)
    for (const { id } of API_SPECS) {
      const label = en.pages.apiDocs.specs[id as keyof typeof en.pages.apiDocs.specs]
      expect(label, `no en label for spec "${id}"`).toBeTypeOf('string')
      expect(screen.getByRole('tab', { name: label })).toBeInTheDocument()
    }
    expect(screen.getAllByRole('tab')).toHaveLength(API_SPECS.length)
  })

  it('renders SwaggerUI bound to the Identity spec by default', () => {
    render(
      <MemoryRouter>
        <ApiDocsPage />
      </MemoryRouter>,
    )

    // Default active spec is "identity" → identity-service.yaml.
    const swagger = screen.getAllByTestId('swagger-ui')
    expect(swagger.length).toBeGreaterThan(0)
    expect(swagger[0].textContent).toMatch(/identity-service\.yaml/)
  })
})
