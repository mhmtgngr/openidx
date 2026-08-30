import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { AssignmentReportPage } from './assignment-report'

const get = vi.fn()
vi.mock('../lib/api', () => ({ api: { get: (...a: unknown[]) => get(...a) } }))

const renderPage = () =>
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <AssignmentReportPage />
      </MemoryRouter>
    </QueryClientProvider>
  )

describe('AssignmentReportPage', () => {
  beforeEach(() => get.mockReset())

  it('lists who would lose which application', async () => {
    get.mockResolvedValue({
      entries: [
        { user_id: 'u1', username: 'mehmet.gungor', application_id: 'a1', application_name: 'Es-Dev', enforcement_point: 'ziti', reason: 'no assignment' },
      ],
      summary: { users: 1, applications: 1, would_deny: 1, incomplete_users: 0 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText('mehmet.gungor')).toBeInTheDocument())
    expect(screen.getByText('Es-Dev')).toBeInTheDocument()
  })

  it('says so when enforcing would take nothing away', async () => {
    get.mockResolvedValue({ entries: [], summary: { users: 0, applications: 0, would_deny: 0, incomplete_users: 0 } })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no one would lose access/i)).toBeInTheDocument()
    )
  })

  it('qualifies the clean headline when users could not be evaluated', async () => {
    // A report that failed to evaluate part of the org must not read
    // identically to a genuinely clean one — that false confidence is exactly
    // what incomplete_users exists to prevent.
    get.mockResolvedValue({ entries: [], summary: { users: 0, applications: 0, would_deny: 0, incomplete_users: 3 } })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no one would lose access/i)).toBeInTheDocument()
    )
    expect(screen.getByText(/3 users? could not be evaluated/i)).toBeInTheDocument()
  })

  it('surfaces incomplete_users even when entries are present', async () => {
    get.mockResolvedValue({
      entries: [
        { user_id: 'u1', username: 'mehmet.gungor', application_id: 'a1', application_name: 'Es-Dev', enforcement_point: 'ziti', reason: 'no assignment' },
      ],
      summary: { users: 1, applications: 1, would_deny: 1, incomplete_users: 2 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText('mehmet.gungor')).toBeInTheDocument())
    expect(screen.getByText(/2 users? could not be evaluated/i)).toBeInTheDocument()
  })
})
