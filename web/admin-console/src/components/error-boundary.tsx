import { Component, ErrorInfo, ReactNode } from 'react'

interface Props {
  children: ReactNode
  /**
   * What "Try again" should do. The default just clears the boundary's own
   * state, which is the right thing for the per-route boundary inside the
   * layout: the route remounts and usually succeeds. It is the WRONG thing
   * at the root, where the thing that threw is the app shell itself --
   * clearing state there re-renders the same broken tree and throws again
   * on the next frame. The root mount passes a reload.
   */
  onReset?: () => void
}

interface State {
  hasError: boolean
  error: Error | null
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('[ErrorBoundary] Uncaught error:', error)
    console.error('[ErrorBoundary] Component stack:', errorInfo.componentStack)
  }

  handleReset = (): void => {
    if (this.props.onReset) {
      this.props.onReset()
      return
    }
    this.setState({ hasError: false, error: null })
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-background p-4">
          <div className="w-full max-w-md rounded-lg border border-border bg-card p-8 shadow-lg">
            <div className="flex flex-col items-center text-center">
              {/* Error Icon */}
              <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-8 w-8 text-destructive"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                  />
                </svg>
              </div>

              <h2 className="mb-2 text-xl font-semibold text-foreground">
                Something went wrong
              </h2>

              {this.state.error && (
                <p className="mb-4 text-sm text-muted-foreground">
                  {this.state.error.message}
                </p>
              )}

              {/* The stack is a developer aid. Since this boundary now also
                  wraps the whole app -- including the login screen, which
                  anyone can reach -- it is shown in development only. The
                  message above stays: it is what a user quotes to support,
                  and componentDidCatch still logs the full stack to the
                  console in every build. */}
              {import.meta.env.DEV && this.state.error && (
                <pre className="mb-6 max-h-32 w-full overflow-auto rounded-md bg-muted p-3 text-left text-xs text-muted-foreground">
                  {this.state.error.stack}
                </pre>
              )}

              <button
                onClick={this.handleReset}
                className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow-sm transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              >
                Try again
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export { ErrorBoundary }
