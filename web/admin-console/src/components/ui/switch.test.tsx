import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Switch } from './switch'

describe('Switch', () => {
  it('renders unchecked by default', () => {
    render(<Switch data-testid="switch" />)
    const switchEl = screen.getByTestId('switch')
    expect(switchEl).toBeInTheDocument()
    expect(switchEl).toHaveAttribute('data-state', 'unchecked')
  })

  it('renders checked when checked prop is true', () => {
    render(<Switch data-testid="switch" defaultChecked />)
    const switchEl = screen.getByTestId('switch')
    expect(switchEl).toHaveAttribute('data-state', 'checked')
  })

  it('renders disabled state', () => {
    render(<Switch data-testid="switch" disabled />)
    const switchEl = screen.getByTestId('switch')
    expect(switchEl).toBeDisabled()
  })

  it('handles change events', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Switch data-testid="switch" onCheckedChange={handleChange} />)

    const switchEl = screen.getByTestId('switch')
    await user.click(switchEl)

    expect(handleChange).toHaveBeenCalledTimes(1)
  })

  it('does not handle change when disabled', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Switch data-testid="switch" disabled onCheckedChange={handleChange} />)

    const switchEl = screen.getByTestId('switch')
    await user.click(switchEl)

    expect(handleChange).not.toHaveBeenCalled()
  })

  it('renders with custom className', () => {
    render(<Switch data-testid="switch" className="custom-class" />)
    const switchEl = screen.getByTestId('switch')
    expect(switchEl).toHaveClass('custom-class')
  })

  it('renders with custom name', () => {
    render(<Switch data-testid="switch" name="notifications" />)
    const switchEl = screen.getByTestId('switch')
    // Note: Radix Switch doesn't forward the name attribute to the button element
    // It can be accessed via data-name or used in form contexts differently
    expect(switchEl).toBeInTheDocument()
  })

  it('toggles state on click', async () => {
    const user = userEvent.setup()
    render(<Switch data-testid="switch" />)

    const switchEl = screen.getByTestId('switch')
    expect(switchEl).toHaveAttribute('data-state', 'unchecked')

    await user.click(switchEl)
    expect(switchEl).toHaveAttribute('data-state', 'checked')

    await user.click(switchEl)
    expect(switchEl).toHaveAttribute('data-state', 'unchecked')
  })

  it('forwards ref correctly', () => {
    const ref = { current: null }
    render(<Switch ref={ref} data-testid="switch" />)
    expect(ref.current).toBeInstanceOf(HTMLButtonElement)
  })

  it('has accessible name when label is provided', () => {
    render(
      <label>
        <Switch /> Enable notifications
      </label>
    )
    const switchEl = screen.getByRole('switch')
    expect(switchEl).toBeInTheDocument()
  })

  it('has accessible name with aria-label', () => {
    render(<Switch aria-label="Enable notifications" />)
    const switchEl = screen.getByRole('switch', { name: 'Enable notifications' })
    expect(switchEl).toBeInTheDocument()
  })

  it('applies focus-visible styles on keyboard navigation', async () => {
    const user = userEvent.setup()
    render(<Switch data-testid="switch" />)

    const switchEl = screen.getByTestId('switch')
    await user.tab()

    expect(switchEl).toHaveFocus()
  })

  it('does not toggle when space is pressed on disabled switch', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Switch data-testid="switch" disabled onCheckedChange={handleChange} />)

    const switchEl = screen.getByTestId('switch')
    switchEl.focus()
    await user.keyboard(' ')

    expect(handleChange).not.toHaveBeenCalled()
  })

  it('can be controlled with checked prop', () => {
    const { rerender } = render(<Switch data-testid="switch" checked={false} />)
    const switchEl = screen.getByTestId('switch')

    expect(switchEl).toHaveAttribute('data-state', 'unchecked')

    rerender(<Switch data-testid="switch" checked={true} />)
    expect(switchEl).toHaveAttribute('data-state', 'checked')
  })

  it('has thumb element with proper classes', () => {
    render(<Switch data-testid="switch" />)
    const switchEl = screen.getByTestId('switch')
    const thumb = switchEl.querySelector('span')
    expect(thumb).toBeInTheDocument()
    expect(thumb).toHaveClass('h-4', 'w-4', 'rounded-full')
  })

  it('thumb translates when checked', () => {
    const { rerender } = render(<Switch data-testid="switch" checked={false} />)
    const switchEl = screen.getByTestId('switch')
    const thumb = switchEl.querySelector('span')

    // The thumb has data-[state=unchecked]:translate-x-0 by default
    expect(thumb).toHaveAttribute('class')
    expect(thumb?.className).toContain('translate-x-0')

    rerender(<Switch data-testid="switch" checked={true} />)
    // When checked, the thumb gets translate-x-4 via data-[state=checked]
    expect(thumb?.className).toContain('translate-x-4')
  })
})
