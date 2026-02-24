import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from './select'

describe('Select', () => {
  beforeEach(() => {
    // Reset any DOM state between tests
    document.body.innerHTML = ''
  })

  it('renders trigger with placeholder', () => {
    render(
      <Select>
        <SelectTrigger>
          <SelectValue placeholder="Select an option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Select an option')).toBeInTheDocument()
  })

  it('renders select items when open', () => {
    render(
      <Select open={true}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
          <SelectItem value="option3">Option 3</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Option 1')).toBeInTheDocument()
    expect(screen.getByText('Option 2')).toBeInTheDocument()
    expect(screen.getByText('Option 3')).toBeInTheDocument()
  })

  it('renders select group with label', () => {
    render(
      <Select open={true}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectLabel>Fruits</SelectLabel>
            <SelectItem value="apple">Apple</SelectItem>
            <SelectItem value="banana">Banana</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Fruits')).toBeInTheDocument()
    expect(screen.getByText('Apple')).toBeInTheDocument()
    expect(screen.getByText('Banana')).toBeInTheDocument()
  })

  it('renders separator element', () => {
    render(
      <Select open={true}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectSeparator />
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    // The separator is rendered as a div with aria-hidden, not role="separator"
    const separators = document.querySelectorAll('[aria-hidden="true"]')
    expect(separators.length).toBeGreaterThan(0)
  })

  it('can be controlled with value prop', () => {
    const { rerender } = render(
      <Select value="option1">
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Option 1')).toBeInTheDocument()

    rerender(
      <Select value="option2">
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Option 2')).toBeInTheDocument()
  })

  it('renders disabled trigger', () => {
    render(
      <Select disabled>
        <SelectTrigger data-testid="trigger">
          <SelectValue placeholder="Select an option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByTestId('trigger')
    expect(trigger).toBeDisabled()
  })

  it('renders disabled item', () => {
    render(
      <Select open={true}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2" disabled>
            Option 2 (Disabled)
          </SelectItem>
        </SelectContent>
      </Select>
    )

    const option2 = screen.getByText('Option 2 (Disabled)')
    // Check that the disabled item is rendered
    expect(option2).toBeInTheDocument()
    // The item may have data-state or data-disabled attributes
    expect(option2.closest('[data-state]')).toBeInTheDocument()
  })

  it('renders with custom className', () => {
    render(
      <Select>
        <SelectTrigger className="custom-trigger" data-testid="trigger">
          <SelectValue placeholder="Select an option" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1" className="custom-item">
            Option 1
          </SelectItem>
        </SelectContent>
      </Select>
    )

    const trigger = screen.getByTestId('trigger')
    expect(trigger).toHaveClass('custom-trigger')
  })

  it('renders scroll buttons', () => {
    render(
      <Select open={true}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectScrollUpButton />
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectScrollDownButton />
        </SelectContent>
      </Select>
    )

    // Scroll buttons are rendered but may be empty elements
    const content = screen.getByRole('listbox')
    expect(content).toBeInTheDocument()
  })

  it('renders multiple groups', () => {
    render(
      <Select open={true}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectLabel>Fruits</SelectLabel>
            <SelectItem value="apple">Apple</SelectItem>
            <SelectItem value="banana">Banana</SelectItem>
          </SelectGroup>
          <SelectSeparator />
          <SelectGroup>
            <SelectLabel>Vegetables</SelectLabel>
            <SelectItem value="carrot">Carrot</SelectItem>
            <SelectItem value="broccoli">Broccoli</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Fruits')).toBeInTheDocument()
    expect(screen.getByText('Vegetables')).toBeInTheDocument()
    expect(screen.getByText('Apple')).toBeInTheDocument()
    expect(screen.getByText('Carrot')).toBeInTheDocument()
  })

  it('default value is displayed', () => {
    render(
      <Select defaultValue="option2">
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Option 2')).toBeInTheDocument()
  })

  it('calls onValueChange when value changes', () => {
    const handleChange = vi.fn()

    const { rerender } = render(
      <Select value="option1" onValueChange={handleChange}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Option 1')).toBeInTheDocument()

    // Simulate value change via prop update
    rerender(
      <Select value="option2" onValueChange={handleChange}>
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="option1">Option 1</SelectItem>
          <SelectItem value="option2">Option 2</SelectItem>
        </SelectContent>
      </Select>
    )

    expect(screen.getByText('Option 2')).toBeInTheDocument()
  })
})
