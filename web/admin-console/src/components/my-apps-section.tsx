import { useQuery } from '@tanstack/react-query'
import { AppWindow, ExternalLink } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { QueryError } from './query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface UserApp {
  id: string
  name: string
  description: string
  base_url: string
  protocol: string
  logo_url: string
  sso_enabled: boolean
}

/**
 * MyAppsSection renders the user's single-sign-on applications as launchable
 * tiles. It is the "Sign in to your apps" half of the combined My Apps & Network
 * page; the caller owns the shared search box and passes the term in. The whole
 * section hides itself when the user has no assigned apps, so it never adds an
 * empty block above the network resources.
 */
export function MyAppsSection({ search }: { search: string }) {
  const { toast } = useToast()

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['my-applications'],
    queryFn: () => api.get<{ applications: UserApp[] }>('/api/v1/identity/portal/applications'),
  })

  const term = search.trim().toLowerCase()
  const apps = (data?.applications || []).filter(a =>
    !term || a.name.toLowerCase().includes(term) || a.description.toLowerCase().includes(term)
  )

  const launchApp = (app: UserApp) => {
    // Only open a real absolute http(s) URL. A blank/whitespace/relative
    // base_url previously produced window.open('') → an about:blank tab with an
    // empty address bar (QA 12.2, SecureTask had no launch URL configured).
    const url = app.base_url?.trim()
    if (url && /^https?:\/\//i.test(url)) {
      window.open(url, '_blank', 'noopener,noreferrer')
    } else {
      toast({
        title: 'Cannot launch application',
        description: `${app.name} has no valid launch URL configured. Contact your administrator.`,
        variant: 'destructive',
      })
    }
  }

  // Hide the whole section when the user has no apps at all (not just no search
  // match) — the network section below carries the page on its own.
  if (!isLoading && !isError && (data?.applications || []).length === 0) {
    return null
  }

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Sign in to your apps</h2>
        <p className="text-sm text-muted-foreground">
          Click one and OpenIDX signs you in automatically (single sign-on) — no separate password.
        </p>
      </div>

      {isLoading ? (
        <p className="text-center py-8 text-muted-foreground">Loading applications...</p>
      ) : isError ? (
        <QueryError error={error} resource="applications" />
      ) : apps.length === 0 ? (
        <p className="text-sm text-muted-foreground">No apps match “{search}”.</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {apps.map(app => (
            <Card key={app.id} className="hover:shadow-lg transition-shadow cursor-pointer group" onClick={() => launchApp(app)}>
              <CardHeader className="pb-3">
                <div className="flex items-center gap-3">
                  {app.logo_url ? (
                    <img src={app.logo_url} alt={app.name} className="h-10 w-10 rounded-lg object-cover" />
                  ) : (
                    <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                      <AppWindow className="h-6 w-6 text-primary" />
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <CardTitle className="text-base truncate">{app.name}</CardTitle>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="text-xs">{app.protocol}</Badge>
                      {app.sso_enabled && <Badge variant="secondary" className="text-xs">SSO</Badge>}
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground line-clamp-2 mb-3">{app.description || 'No description available'}</p>
                <Button variant="outline" size="sm" className="w-full group-hover:bg-blue-50 group-hover:text-blue-700 group-hover:border-blue-200">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  Launch
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </section>
  )
}
