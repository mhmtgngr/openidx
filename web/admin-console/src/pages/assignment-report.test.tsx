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

const CONTROLLER_WARNING =
  /could not read the ziti controller, so this report cannot tell you who would lose access\. do not enable enforcement based on this page\./i

describe('AssignmentReportPage', () => {
  beforeEach(() => get.mockReset())

  it('lists who would lose which application', async () => {
    get.mockResolvedValue({
      entries: [
        { user_id: 'u1', username: 'mehmet.gungor', application_id: 'a1', application_name: 'Es-Dev', enforcement_point: 'ziti', reason: 'no assignment' },
      ],
      reachability_source: 'controller',
      summary: { users: 1, applications: 1, would_deny: 1, incomplete_users: 0 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText('mehmet.gungor')).toBeInTheDocument())
    expect(screen.getByText('Es-Dev')).toBeInTheDocument()
  })

  it('says so when enforcing would take nothing away', async () => {
    get.mockResolvedValue({
      entries: [],
      reachability_source: 'controller',
      summary: {
        users: 0, applications: 0, would_deny: 0, incomplete_users: 0,
        users_evaluated: 4, users_total: 4, users_without_identity: 0,
        evaluation_complete: true,
      },
    })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no one would lose access/i)).toBeInTheDocument()
    )
    expect(screen.queryByText(CONTROLLER_WARNING)).not.toBeInTheDocument()
    // The denominator is on the page: "safe" is only meaningful next to how
    // much of the org was actually looked at.
    expect(screen.getByText(/evaluated 4 of 4 users/i)).toBeInTheDocument()
  })

  // Every org on this deployment has users with no Ziti identity — service
  // accounts, disabled accounts, admins who never onboarded. They have no Ziti
  // reach and therefore no Ziti reach to lose, so they must not withhold the
  // headline; a go/no-go that is permanently amber is one operators learn to
  // ignore. But the count has to stay visible so an operator can decide whether
  // any of them SHOULD have been enrolled.
  it('shows the without-identity line alongside a clean headline', async () => {
    get.mockResolvedValue({
      entries: [],
      reachability_source: 'controller',
      summary: {
        users: 0, applications: 0, would_deny: 0, incomplete_users: 0,
        users_evaluated: 4, users_total: 6, users_without_identity: 2,
        evaluation_complete: true,
      },
    })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no one would lose access/i)).toBeInTheDocument()
    )
    expect(screen.getByText(/evaluated 4 of 6 users/i)).toBeInTheDocument()
    expect(
      screen.getByText(/2 of 6 users in this organization have no ziti identity/i)
    ).toBeInTheDocument()
  })

  // The rule lives on the server, which computes it once for every consumer.
  // These four fields re-derive to "clean" — controller, nothing denied, nobody
  // incomplete, 4 of 4 evaluated — so a page that re-derived the rule would
  // print the reassuring headline over a server that said not to.
  it('reads evaluation_complete rather than re-deriving the rule', async () => {
    get.mockResolvedValue({
      entries: [],
      reachability_source: 'controller',
      summary: {
        users: 0, applications: 0, would_deny: 0, incomplete_users: 0,
        users_evaluated: 4, users_total: 4, users_without_identity: 0,
        evaluation_complete: false,
      },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText(/report incomplete/i)).toBeInTheDocument())
    expect(screen.queryByText(/no one would lose access/i)).not.toBeInTheDocument()
  })

  // An org whose Ziti sync has never run evaluates nobody. Without a
  // denominator that is textually identical to an org that was evaluated in
  // full and found clean — the false confidence this whole endpoint exists to
  // prevent.
  it('withholds the clean headline when some users could not be evaluated', async () => {
    get.mockResolvedValue({
      entries: [],
      reachability_source: 'controller',
      summary: {
        users: 0, applications: 0, would_deny: 0, incomplete_users: 3,
        users_evaluated: 5, users_total: 8, users_without_identity: 0,
        evaluation_complete: false,
      },
    })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/evaluated 5 of 8 users/i)).toBeInTheDocument()
    )
    expect(screen.queryByText(/no one would lose access/i)).not.toBeInTheDocument()
    expect(screen.getByText(/report incomplete/i)).toBeInTheDocument()
    // These three had identities the report could not finish reading — a
    // different thing from having no identity at all, and the alarming one.
    expect(screen.getByText(/3 users could not be evaluated/i)).toBeInTheDocument()
    expect(screen.queryByText(/no ziti identity/i)).not.toBeInTheDocument()
  })

  it('does not read as clean when the organization has no users at all', async () => {
    get.mockResolvedValue({
      entries: [],
      reachability_source: 'controller',
      summary: {
        users: 0, applications: 0, would_deny: 0, incomplete_users: 0,
        users_evaluated: 0, users_total: 0, users_without_identity: 0,
        evaluation_complete: false,
      },
    })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/no users were found in this organization/i)).toBeInTheDocument()
    )
    expect(screen.queryByText(/no one would lose access/i)).not.toBeInTheDocument()
    expect(screen.getByText(/report incomplete/i)).toBeInTheDocument()
  })

  // Fail closed: a response that does not say how much of the org it covered
  // has not shown that it covered all of it. And "did not say" is not "said
  // zero" — the page must not assert an emptiness the response never claimed.
  it('says the counts are missing rather than asserting 0 of 0', async () => {
    get.mockResolvedValue({
      entries: [],
      reachability_source: 'controller',
      summary: { users: 0, applications: 0, would_deny: 0, incomplete_users: 0 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText(/report incomplete/i)).toBeInTheDocument())
    expect(screen.queryByText(/no one would lose access/i)).not.toBeInTheDocument()
    expect(screen.getByText(/user counts not reported by the server/i)).toBeInTheDocument()
    expect(screen.queryByText(/evaluated 0 of 0/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/no users were found in this organization/i)).not.toBeInTheDocument()
  })

  // The reassuring headline is the operator's go/no-go for the one irreversible
  // step of the rollout. It may only appear when the reach half came from the
  // live Ziti controller — never from a report that could not read it, which is
  // the failure that renders "safe to enforce" regardless of the truth.
  it('replaces the clean headline with a warning when the controller could not be read', async () => {
    get.mockResolvedValue({
      entries: [],
      assignments: [],
      reachability_source: 'unavailable',
      reachability_error: 'the Ziti controller is not connected',
      summary: { users: 0, applications: 0, would_deny: 0, incomplete_users: 4 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText(CONTROLLER_WARNING)).toBeInTheDocument())
    expect(screen.queryByText(/no one would lose access/i)).not.toBeInTheDocument()
    expect(screen.getByText('the Ziti controller is not connected')).toBeInTheDocument()
  })

  it('warns rather than reassures when a response carries no reachability source at all', async () => {
    get.mockResolvedValue({
      entries: [],
      summary: { users: 0, applications: 0, would_deny: 0, incomplete_users: 0 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText(CONTROLLER_WARNING)).toBeInTheDocument())
    expect(screen.queryByText(/no one would lose access/i)).not.toBeInTheDocument()
  })

  it('qualifies the clean headline when users could not be evaluated', async () => {
    // A report that failed to evaluate part of the org must not read
    // identically to a genuinely clean one — that false confidence is exactly
    // what incomplete_users exists to prevent.
    get.mockResolvedValue({
      entries: [],
      reachability_source: 'controller',
      summary: { users: 0, applications: 0, would_deny: 0, incomplete_users: 3 },
    })
    renderPage()
    await waitFor(() =>
      expect(screen.getByText(/3 users? could not be evaluated/i)).toBeInTheDocument()
    )
    expect(screen.queryByText(/no one would lose access/i)).not.toBeInTheDocument()
    expect(screen.getByText(/report incomplete/i)).toBeInTheDocument()
  })

  it('surfaces incomplete_users even when entries are present', async () => {
    get.mockResolvedValue({
      entries: [
        { user_id: 'u1', username: 'mehmet.gungor', application_id: 'a1', application_name: 'Es-Dev', enforcement_point: 'ziti', reason: 'no assignment' },
      ],
      reachability_source: 'controller',
      summary: { users: 1, applications: 1, would_deny: 1, incomplete_users: 2 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText('mehmet.gungor')).toBeInTheDocument())
    expect(screen.getByText(/2 users? could not be evaluated/i)).toBeInTheDocument()
  })

  it('still reports what assignment grants when reach is unavailable', async () => {
    get.mockResolvedValue({
      entries: [],
      assignments: [
        { user_id: 'u1', username: 'mehmet.gungor', application_id: 'a1', application_name: 'Es-Dev' },
      ],
      reachability_source: 'unavailable',
      reachability_error: 'could not list service policies: unexpected status 500',
      summary: { users: 0, applications: 0, would_deny: 0, incomplete_users: 1 },
    })
    renderPage()
    await waitFor(() => expect(screen.getByText(CONTROLLER_WARNING)).toBeInTheDocument())
    expect(screen.getByText(/assignment currently grants 1 user–application pair/i)).toBeInTheDocument()
  })
})
