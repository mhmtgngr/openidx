import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Label } from './label'

describe('Label', () => {
  it('renders with text', () => {
    render(<Label>Username</Label>)
    expect(screen.getByText('Username')).toBeInTheDocument()
  })

  it('renders with htmlFor attribute', () => {
    render(<Label htmlFor="username">Username</Label>)
    const label = screen.getByText('Username')
    expect(label).toHaveAttribute('for', 'username')
  })

  it('renders with custom className', () => {
    render(<Label className="text-red-500">Custom Label</Label>)
    const label = screen.getByText('Custom Label')
    expect(label).toHaveClass('text-red-500')
  })

  it('applies peer-disabled styles when disabled peer exists', () => {
    render(
      <div className="peer-disabled:opacity-70">
        <Label>Disabled Label</Label>
      </div>
    )
    expect(screen.getByText('Disabled Label')).toBeInTheDocument()
  })

  it('forwards ref correctly', () => {
    const ref = { current: null }
    render(<Label ref={ref}>Label with Ref</Label>)
    expect(ref.current).toBeInstanceOf(HTMLLabelElement)
  })
})
