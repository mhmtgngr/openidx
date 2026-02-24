import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { LoadingSpinner } from './loading-spinner'

describe('LoadingSpinner', () => {
  it('renders with default size', () => {
    render(<LoadingSpinner />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toBeInTheDocument()
    expect(spinner).toHaveClass('h-8', 'w-8')
  })

  it('renders with small size', () => {
    render(<LoadingSpinner size="sm" />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toHaveClass('h-4', 'w-4')
  })

  it('renders with large size', () => {
    render(<LoadingSpinner size="lg" />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toHaveClass('h-12', 'w-12')
  })

  it('renders with custom className', () => {
    render(<LoadingSpinner className="custom-class" />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toHaveClass('custom-class')
  })

  it('has correct border classes', () => {
    render(<LoadingSpinner />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toHaveClass('border-2', 'border-t-transparent')
  })

  it('has animation class', () => {
    render(<LoadingSpinner />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toHaveClass('animate-spin')
  })
})
