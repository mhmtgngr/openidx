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

    for (const label of [
      'Identity', 'OAuth/OIDC', 'Admin API', 'Access', 'Governance',
      'SCIM', 'Audit', 'Notifications', 'Organizations', 'Portal',
    ]) {
      expect(
        screen.getByRole('tab', { name: label }),
      ).toBeInTheDocument()
    }
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
