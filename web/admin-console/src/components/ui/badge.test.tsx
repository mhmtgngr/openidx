import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Badge } from './badge'

describe('Badge', () => {
  it('renders with text', () => {
    render(<Badge>Active</Badge>)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('renders default variant', () => {
    const { container } = render(<Badge>Default</Badge>)
    expect(container.firstChild).toBeInTheDocument()
  })

  it('renders with custom className', () => {
    const { container } = render(<Badge className="extra-class">Tag</Badge>)
    expect(container.firstChild).toHaveClass('extra-class')
  })
})
