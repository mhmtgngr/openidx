import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from '@/components/ui/toaster'
import { ErrorBoundary } from '@/components/error-boundary'
import { AuthProvider } from '@/lib/auth'
import App from './App'
import './i18n'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
})

// The layout has a per-route boundary, but it sits INSIDE the app shell, so
// anything that throws in the chrome, in AuthProvider, or while resolving a
// route took the whole page down to a blank white screen with no way back --
// verified with a backend returning one wrong-shaped response. This boundary
// is the outermost one, so a crash there becomes a readable card instead.
// Reset reloads rather than clearing state: if the shell itself threw, the
// same tree would throw again on the next frame.
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary onReset={() => window.location.reload()}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <App />
            <Toaster />
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>,
)
