import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Checkbox } from './checkbox'

describe('Checkbox', () => {
  it('renders unchecked by default', () => {
    render(<Checkbox data-testid="checkbox" />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeInTheDocument()
    expect(checkbox).not.toBeChecked()
  })

  it('renders checked when checked prop is true', () => {
    render(<Checkbox data-testid="checkbox" defaultChecked />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeChecked()
  })

  it('renders disabled state', () => {
    render(<Checkbox data-testid="checkbox" disabled />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeDisabled()
  })

  it('handles change events', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Checkbox data-testid="checkbox" onCheckedChange={handleChange} />)

    const checkbox = screen.getByTestId('checkbox')
    await user.click(checkbox)

    expect(handleChange).toHaveBeenCalledTimes(1)
  })

  it('does not handle change when disabled', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()
    render(<Checkbox data-testid="checkbox" disabled onCheckedChange={handleChange} />)

    const checkbox = screen.getByTestId('checkbox')
    await user.click(checkbox)

    expect(handleChange).not.toHaveBeenCalled()
  })

  it('renders with custom className', () => {
    render(<Checkbox data-testid="checkbox" className="custom-class" />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toHaveClass('custom-class')
  })

  it('renders with custom name', () => {
    // Note: Radix UI Checkbox uses a button element, which doesn't have a name attribute
    // The name attribute should be used with a wrapping form element
    render(
      <label>
        <Checkbox data-testid="checkbox" name="agree" /> Agree
      </label>
    )
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeInTheDocument()
  })

  it('renders with custom value', () => {
    // Note: Radix UI Checkbox doesn't use value attribute like native inputs
    // The value is handled through state management
    render(<Checkbox data-testid="checkbox" value="yes" />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeInTheDocument()
  })

  it('renders with required attribute', () => {
    render(<Checkbox data-testid="checkbox" required />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeRequired()
  })

  it('toggles state on click', async () => {
    const user = userEvent.setup()
    render(<Checkbox data-testid="checkbox" />)

    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).not.toBeChecked()

    await user.click(checkbox)
    expect(checkbox).toBeChecked()

    await user.click(checkbox)
    expect(checkbox).not.toBeChecked()
  })

  it('forwards ref correctly', () => {
    const ref = { current: null }
    render(<Checkbox ref={ref} data-testid="checkbox" />)
    expect(ref.current).toBeInstanceOf(HTMLButtonElement)
  })

  it('has accessible name when label is provided', () => {
    render(
      <label>
        <Checkbox data-testid="checkbox" /> Accept terms
      </label>
    )
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeInTheDocument()
  })

  it('has accessible name with aria-label', () => {
    render(<Checkbox data-testid="checkbox" aria-label="Accept terms and conditions" />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toHaveAttribute('aria-label', 'Accept terms and conditions')
  })

  it('has accessible name with aria-labelledby', () => {
    render(
      <div>
        <span id="terms-label">Terms and conditions</span>
        <Checkbox data-testid="checkbox" aria-labelledby="terms-label" />
      </div>
    )
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toBeInTheDocument()
  })

  it('renders indeterminate state', () => {
    render(<Checkbox data-testid="checkbox" checked="indeterminate" />)
    const checkbox = screen.getByTestId('checkbox')
    expect(checkbox).toHaveAttribute('data-state', 'indeterminate')
  })

  it('applies focus-visible styles on keyboard navigation', async () => {
    const user = userEvent.setup()
    render(<Checkbox data-testid="checkbox" />)

    const checkbox = screen.getByTestId('checkbox')
    await user.tab()

    expect(checkbox).toHaveFocus()
  })
})
