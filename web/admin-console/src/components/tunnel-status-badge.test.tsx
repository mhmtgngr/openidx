import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TunnelPolicyBadge, TunnelStatusBadge } from './tunnel-status-badge'

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

  it('shows a tunnel that is not enabled as off', () => {
    render(<TunnelStatusBadge status={{ state: 'off' }} />)
    expect(screen.getByTestId('tunnel-status')).toHaveTextContent('Off')
  })

  it('says how the device applied the policy and what it cannot enforce', () => {
    render(
      <TunnelStatusBadge
        status={{ state: 'up', mode: 'split', policy_gaps: ['block_direct', 'bogus'], last_error: 'nft: not installed' }}
      />,
    )
    const title = screen.getByTestId('tunnel-status').getAttribute('title') ?? ''
    expect(title).toContain('Mode: split')
    expect(title).toContain('Not enforced on this device: blocking direct corporate access')
    expect(title).not.toContain('bogus')
    expect(title).toContain('Last error: nft: not installed')
  })
})

describe('TunnelPolicyBadge', () => {
  it('shows an applied policy with its version', () => {
    render(<TunnelPolicyBadge state="applied" version="0123456789abcdef" appliedAt="2026-10-10T08:00:00Z" />)
    const badge = screen.getByTestId('tunnel-policy')
    expect(badge).toHaveTextContent('Policy applied')
    expect(badge.getAttribute('title')).toContain('0123456789abcdef')
  })

  it('shows a pending policy', () => {
    render(<TunnelPolicyBadge state="pending" version={null} />)
    expect(screen.getByTestId('tunnel-policy')).toHaveTextContent('Policy pending')
  })

  it('shows nothing for a device that reports no tunnel', () => {
    const { container } = render(<TunnelPolicyBadge state="" />)
    expect(container).toBeEmptyDOMElement()
  })
})
