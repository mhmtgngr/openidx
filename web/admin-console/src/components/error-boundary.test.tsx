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

    // Swap the children to a non-throwing variant BEFORE resetting. While the
    // boundary is in its error state it renders the fallback (not children), so
    // this rerender does not re-trigger the throw. Then clicking "Try again"
    // clears hasError and the boundary renders the now-safe children.
    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    )

    const resetButton = screen.getByRole('button', { name: 'Try again' })
    const user = userEvent.setup()
    await user.click(resetButton)

    // After reset, the error state should be cleared and children render.
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

  // The root mount in main.tsx wraps the whole app, including the app shell
  // and the login screen. Both of these pin behaviour that only matters there.
  describe('as the root boundary', () => {
    it('calls onReset instead of clearing its own state', async () => {
      // At the root, clearing state re-renders the same broken shell and
      // throws again, so the root passes a reload. Prove the override wins:
      // the fallback must still be on screen after the click.
      const onReset = vi.fn()
      render(
        <ErrorBoundary onReset={onReset}>
          <ThrowError shouldThrow={true} />
        </ErrorBoundary>
      )

      await userEvent.click(screen.getByRole('button', { name: 'Try again' }))

      expect(onReset).toHaveBeenCalledTimes(1)
      expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    })

    it('does not print a stack trace outside development', () => {
      vi.stubEnv('DEV', false)
      try {
        const { container } = render(
          <ErrorBoundary>
            <ThrowError shouldThrow={true} />
          </ErrorBoundary>
        )

        // The message a user can quote to support stays; the stack does not.
        expect(screen.getByText('Test error')).toBeInTheDocument()
        expect(container.querySelector('pre')).toBeNull()
      } finally {
        vi.unstubAllEnvs()
      }
    })

    it('prints the stack in development', () => {
      vi.stubEnv('DEV', true)
      try {
        const { container } = render(
          <ErrorBoundary>
            <ThrowError shouldThrow={true} />
          </ErrorBoundary>
        )
        expect(container.querySelector('pre')).not.toBeNull()
      } finally {
        vi.unstubAllEnvs()
      }
    })
  })
})
