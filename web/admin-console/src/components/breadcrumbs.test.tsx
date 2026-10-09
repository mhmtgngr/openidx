import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Breadcrumbs } from './breadcrumbs'

describe('Breadcrumbs', () => {
  it('renders the item name for a matched route', () => {
    render(
      <MemoryRouter initialEntries={['/users']}>
        <Breadcrumbs />
      </MemoryRouter>
    )
    expect(screen.getByText('Users')).toBeInTheDocument()
  })

  it('renders the domain label alongside the item', () => {
    render(
      <MemoryRouter initialEntries={['/users']}>
        <Breadcrumbs />
      </MemoryRouter>
    )
    // Users lives under the Identity group.
    expect(screen.getByText('Identity')).toBeInTheDocument()
  })

  it('links the parent page of a child route', () => {
    render(
      <MemoryRouter initialEntries={['/vault-secrets']}>
        <Breadcrumbs />
      </MemoryRouter>
    )
    expect(screen.getByText('Resources & Access')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'PAM Overview' })).toHaveAttribute('href', '/pam-dashboard')
    expect(screen.getByText('Vault Secrets')).toBeInTheDocument()
  })

  it('renders nothing on /dashboard', () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Breadcrumbs />
      </MemoryRouter>
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing on the root route', () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/']}>
        <Breadcrumbs />
      </MemoryRouter>
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing for an unmatched route', () => {
    const { container } = render(
      <MemoryRouter initialEntries={['/does-not-exist']}>
        <Breadcrumbs />
      </MemoryRouter>
    )
    expect(container).toBeEmptyDOMElement()
  })
})
