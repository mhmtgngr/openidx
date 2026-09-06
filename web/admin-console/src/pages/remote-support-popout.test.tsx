import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const relayProps = vi.fn()
vi.mock('../components/remote-support/relay-renderer', () => ({
  RelayRenderer: (props: Record<string, unknown>) => {
    relayProps(props)
    return <div data-testid="relay" />
  },
}))

vi.mock('../lib/api', () => ({ baseURL: 'https://openidx.example' }))

import { RemoteSupportPopout } from './remote-support-popout'

// The chrome-less window an operator pulls a live remote-support session into.
// `mode=interactive` is keyboard and mouse injection into someone else's
// desktop, chosen by a query parameter, and the page had no test.

function renderAt(search: string) {
  return render(
    <MemoryRouter initialEntries={[`/remote-support/live${search}`]}>
      <RemoteSupportPopout />
    </MemoryRouter>,
  )
}

describe('RemoteSupportPopout', () => {
  beforeEach(() => {
    relayProps.mockClear()
  })

  it('opens nothing when the URL carries no relay path', () => {
    renderAt('?session=abc')
    expect(screen.queryByTestId('relay')).not.toBeInTheDocument()
    expect(relayProps).not.toHaveBeenCalled()
    expect(screen.getByText(/missing/i)).toBeInTheDocument()
  })

  it('builds the websocket URL from the API base', () => {
    renderAt('?session=abcdef123456&ws=/api/v1/access/support/relay/abc&mode=view')
    expect(relayProps).toHaveBeenCalledWith(
      expect.objectContaining({ wsUrl: 'wss://openidx.example/api/v1/access/support/relay/abc' }),
    )
  })

  it('grants interactive control only when the URL asks for it by name', () => {
    renderAt('?ws=/relay/a&mode=interactive')
    expect(relayProps).toHaveBeenCalledWith(expect.objectContaining({ mode: 'interactive' }))
  })

  it.each([
    ['no mode at all', '?ws=/relay/a'],
    ['view', '?ws=/relay/a&mode=view'],
    ['a typo', '?ws=/relay/a&mode=interactve'],
    ['an empty value', '?ws=/relay/a&mode='],
    ['something else entirely', '?ws=/relay/a&mode=admin'],
  ])('falls back to view-only for %s', (_label, search) => {
    renderAt(search)
    expect(relayProps).toHaveBeenCalledWith(expect.objectContaining({ mode: 'view' }))
  })
})
