import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ErrorBoundary } from './error-boundary'

// Throw error component for testing
const ThrowError = ({ shouldThrow = false }: { shouldThrow?: boolean }) => {
  if (shouldThrow) {
    throw new Error('Test error')
  }
  return <div>Normal content</div>
}

describe('ErrorBoundary', () => {
  const originalError = console.error

  beforeEach(() => {
    vi.clearAllMocks()
    console.error = vi.fn()
  })

  afterEach(() => {
    console.error = originalError
  })

  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary>
        <div>Test child content</div>
      </ErrorBoundary>
    )

    expect(screen.getByText('Test child content')).toBeInTheDocument()
  })

  it('catches errors and displays error UI', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })

  it('displays error message when an error occurs', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )

    expect(screen.getByText('Test error')).toBeInTheDocument()
  })

  it('has a reset button to recover from error', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )

    const resetButton = screen.getByRole('button', { name: 'Try again' })
    expect(resetButton).toBeInTheDocument()
  })

  it('resets error state when reset button is clicked', async () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()

    const resetButton = screen.getByRole('button', { name: 'Try again' })
    const user = userEvent.setup()
    await user.click(resetButton)

    // After reset, the error state should be cleared
    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    )

    expect(screen.getByText('Normal content')).toBeInTheDocument()
  })

  it('logs error to console', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )

    expect(console.error).toHaveBeenCalled()
  })

  it('renders error icon in error UI', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )

    // Check for the warning icon (SVG)
    const errorIcon = document.querySelector('svg')
    expect(errorIcon).toBeInTheDocument()
  })

  it('displays error message even when no message provided', () => {
    const ThrowErrorWithoutMessage = () => {
      throw new Error()
    }

    render(
      <ErrorBoundary>
        <ThrowErrorWithoutMessage />
      </ErrorBoundary>
    )

    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })
})
