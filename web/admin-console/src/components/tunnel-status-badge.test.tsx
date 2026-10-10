import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TunnelStatusBadge } from './tunnel-status-badge'

describe('TunnelStatusBadge', () => {
  it('says when an agent never reported its tunnel', () => {
    render(<TunnelStatusBadge status={null} />)
    expect(screen.getByText('not reported')).toBeInTheDocument()
  })

  it('shows the reported state with its details in the title', () => {
    render(
      <TunnelStatusBadge
        status={{ state: 'up', version: '1.5.0', services: [{ name: 'a' }, { name: 'b' }] }}
        lastSeen="2026-10-10T08:00:00Z"
      />,
    )
    const badge = screen.getByTestId('tunnel-status')
    expect(badge).toHaveTextContent('Up')
    expect(badge.getAttribute('title')).toContain('1.5.0')
    expect(badge.getAttribute('title')).toContain('2 services')
  })

  it('shows a state it does not know as unknown', () => {
    render(<TunnelStatusBadge status={{ state: 'exploded' }} />)
    expect(screen.getByTestId('tunnel-status')).toHaveTextContent('Unknown')
  })

  it('marks a down tunnel', () => {
    render(<TunnelStatusBadge status={{ state: 'down' }} />)
    expect(screen.getByTestId('tunnel-status')).toHaveTextContent('Down')
  })
})
