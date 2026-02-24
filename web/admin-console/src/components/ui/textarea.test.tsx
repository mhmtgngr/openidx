import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Textarea } from './textarea'

describe('Textarea', () => {
  it('renders with default props', () => {
    render(<Textarea />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toBeInTheDocument()
  })

  it('renders with placeholder', () => {
    render(<Textarea placeholder="Enter text here" />)
    const textarea = screen.getByPlaceholderText('Enter text here')
    expect(textarea).toBeInTheDocument()
  })

  it('renders with default value', () => {
    render(<Textarea defaultValue="Default value" />)
    const textarea = screen.getByRole('textbox') as HTMLTextAreaElement
    expect(textarea.value).toBe('Default value')
  })

  it('renders with custom className', () => {
    render(<Textarea className="custom-class" />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toHaveClass('custom-class')
  })

  it('can be disabled', () => {
    render(<Textarea disabled />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toBeDisabled()
  })

  it('can be readonly', () => {
    render(<Textarea readOnly />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toHaveAttribute('readonly')
  })

  it('has required attribute when specified', () => {
    render(<Textarea required />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toBeRequired()
  })

  it('has name attribute', () => {
    render(<Textarea name="description" />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toHaveAttribute('name', 'description')
  })

  it('handles user input', async () => {
    const user = userEvent.setup()
    render(<Textarea />)

    const textarea = screen.getByRole('textbox') as HTMLTextAreaElement
    await user.type(textarea, 'Hello world')

    expect(textarea.value).toBe('Hello world')
  })

  it('calls onChange handler', async () => {
    const user = userEvent.setup()
    const handleChange = vi.fn()

    render(<Textarea onChange={handleChange} />)

    const textarea = screen.getByRole('textbox')
    await user.type(textarea, 'a')

    expect(handleChange).toHaveBeenCalled()
  })

  it('has minimum height class', () => {
    render(<Textarea />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toHaveClass('min-h-[60px]')
  })

  it('focuses correctly', async () => {
    const user = userEvent.setup()
    render(<Textarea />)

    const textarea = screen.getByRole('textbox')
    await user.click(textarea)

    expect(textarea).toHaveFocus()
  })
})
