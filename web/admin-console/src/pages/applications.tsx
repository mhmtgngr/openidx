import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Globe, Smartphone, Server, ExternalLink } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { api } from '../lib/api'

interface Application {
  id: string
  client_id: string
  name: string
  description: string
  type: string
  protocol: string
  base_url: string
  redirect_uris: string[]
  enabled: boolean
  created_at: string
  updated_at: string
}

const typeIcons: Record<string, React.ReactNode> = {
  web: <Globe className="h-5 w-5 text-blue-700" />,
  native: <Smartphone className="h-5 w-5 text-green-700" />,
  service: <Server className="h-5 w-5 text-orange-700" />,
}

const typeColors: Record<string, string> = {
  web: 'bg-blue-100',
  native: 'bg-green-100',
  service: 'bg-orange-100',
}

export function ApplicationsPage() {
  const [search, setSearch] = useState('')

  const { data: applications, isLoading } = useQuery({
    queryKey: ['applications', search],
    queryFn: () => api.get<Application[]>('/api/v1/applications'),
  })

  const filteredApps = applications?.filter(app =>
    app.name.toLowerCase().includes(search.toLowerCase()) ||
    app.client_id.toLowerCase().includes(search.toLowerCase()) ||
    app.description?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Applications</h1>
          <p className="text-muted-foreground">Manage registered applications and SSO configurations</p>
        </div>
        <Button>
          <Plus className="mr-2 h-4 w-4" /> Register Application
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                placeholder="Search applications..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-gray-50">
                  <th className="p-3 text-left text-sm font-medium">Application</th>
                  <th className="p-3 text-left text-sm font-medium">Client ID</th>
                  <th className="p-3 text-left text-sm font-medium">Type</th>
                  <th className="p-3 text-left text-sm font-medium">Protocol</th>
                  <th className="p-3 text-left text-sm font-medium">Status</th>
                  <th className="p-3 text-right text-sm font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={6} className="p-4 text-center">Loading...</td></tr>
                ) : filteredApps?.length === 0 ? (
                  <tr><td colSpan={6} className="p-4 text-center">No applications found</td></tr>
                ) : (
                  filteredApps?.map((app) => (
                    <tr key={app.id} className="border-b hover:bg-gray-50">
                      <td className="p-3">
                        <div className="flex items-center gap-3">
                          <div className={`h-10 w-10 rounded-lg ${typeColors[app.type] || 'bg-gray-100'} flex items-center justify-center`}>
                            {typeIcons[app.type] || <Globe className="h-5 w-5 text-gray-700" />}
                          </div>
                          <div>
                            <p className="font-medium">{app.name}</p>
                            <p className="text-sm text-gray-500 max-w-xs truncate">{app.description || '-'}</p>
                          </div>
                        </div>
                      </td>
                      <td className="p-3">
                        <code className="text-sm bg-gray-100 px-2 py-1 rounded">{app.client_id}</code>
                      </td>
                      <td className="p-3">
                        <Badge variant="outline" className="capitalize">
                          {app.type}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <span className="text-sm text-gray-600 uppercase">{app.protocol}</span>
                      </td>
                      <td className="p-3">
                        <Badge variant={app.enabled ? 'default' : 'secondary'}>
                          {app.enabled ? 'Active' : 'Disabled'}
                        </Badge>
                      </td>
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {app.base_url && (
                            <Button variant="ghost" size="icon" asChild>
                              <a href={app.base_url} target="_blank" rel="noopener noreferrer">
                                <ExternalLink className="h-4 w-4" />
                              </a>
                            </Button>
                          )}
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
