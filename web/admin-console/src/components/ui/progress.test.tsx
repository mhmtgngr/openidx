import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { Progress } from './progress'

describe('Progress', () => {
  it('renders with default props', () => {
    const { container } = render(<Progress />)
    // Component renders with base classes
    const root = container.firstChild as HTMLElement
    expect(root).toBeInTheDocument()
    expect(root).toHaveClass('h-2', 'w-full')
  })

  it('renders with value', () => {
    const { container } = render(<Progress value={50} />)
    const root = container.firstChild as HTMLElement
    expect(root).toBeInTheDocument()
  })

  it('renders with 0 value', () => {
    const { container } = render(<Progress value={0} />)
    const root = container.firstChild as HTMLElement
    expect(root).toBeInTheDocument()
  })

  it('renders with 100 value (complete)', () => {
    const { container } = render(<Progress value={100} />)
    const root = container.firstChild as HTMLElement
    expect(root).toBeInTheDocument()
  })

  it('renders with undefined value (indeterminate)', () => {
    const { container } = render(<Progress />)
    const root = container.firstChild as HTMLElement
    expect(root).toBeInTheDocument()
  })

  it('renders with custom className', () => {
    const { container } = render(<Progress value={50} className="custom-progress" />)
    const progress = container.querySelector('.custom-progress')
    expect(progress).toBeInTheDocument()
  })

  it('has proper base classes', () => {
    const { container } = render(<Progress />)
    const progress = container.firstChild as HTMLElement
    expect(progress).toHaveClass('h-2', 'w-full', 'overflow-hidden', 'rounded-full')
  })

  it('has transition class on indicator', () => {
    const { container } = render(<Progress value={30} />)
    const root = container.firstChild as HTMLElement
    // Check that there's a child element for the indicator
    const child = root.querySelector('div') as HTMLElement
    expect(child).toBeInTheDocument()
    expect(child.className).toContain('transition-all')
  })

  it('is accessible', () => {
    const { container } = render(<Progress value={50} aria-label="Loading progress" />)
    const progress = container.querySelector('[aria-label="Loading progress"]')
    expect(progress).toBeInTheDocument()
  })

  it('renders without errors when value is null', () => {
    const { container } = render(<Progress value={null} />)
    const root = container.firstChild as HTMLElement
    expect(root).toBeInTheDocument()
  })

  it('has child indicator element', () => {
    const { container } = render(<Progress value={75} />)
    const root = container.firstChild as HTMLElement
    const child = root.querySelector('div')
    expect(child).toBeInTheDocument()
  })
})
