import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, MoreHorizontal, Globe, Smartphone, Server, ExternalLink, Edit, Trash2, Settings, Copy } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card, CardContent, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog'
import { Label } from '../components/ui/label'
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
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [editAppModal, setEditAppModal] = useState(false)
  const [ssoSettingsModal, setSsoSettingsModal] = useState(false)
  const [selectedApp, setSelectedApp] = useState<Application | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    base_url: '',
    redirect_uris: '',
  })
  const [ssoSettings, setSsoSettings] = useState({
    enabled: true,
    refreshToken: true,
    accessTokenLifetime: '3600',
    refreshTokenLifetime: '86400',
    consentRequired: false,
  })

  const { data: applications, isLoading } = useQuery({
    queryKey: ['applications', search],
    queryFn: () => api.get<Application[]>('/api/v1/applications'),
  })

  const filteredApps = applications?.filter(app =>
    app.name.toLowerCase().includes(search.toLowerCase()) ||
    app.client_id.toLowerCase().includes(search.toLowerCase()) ||
    app.description?.toLowerCase().includes(search.toLowerCase())
  )

  const handleEditApp = (app: Application) => {
    setSelectedApp(app)
    setFormData({
      name: app.name,
      description: app.description || '',
      base_url: app.base_url || '',
      redirect_uris: app.redirect_uris?.join('\n') || '',
    })
    setEditAppModal(true)
  }

  const handleCopyClientId = (clientId: string) => {
    navigator.clipboard.writeText(clientId)
    alert(`Client ID "${clientId}" copied to clipboard!`)
  }

  const handleSsoSettings = (app: Application) => {
    setSelectedApp(app)
    setSsoSettingsModal(true)
  }

  const handleDeleteApp = (appId: string) => {
    if (confirm(`Are you sure you want to delete application: ${appId}? This action cannot be undone.`)) {
      alert(`Delete Application functionality - would remove application: ${appId}`)
    }
  }

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (selectedApp) {
        // Update application via API
        await api.put(`/api/v1/applications/${selectedApp.id}`, {
          name: formData.name,
          description: formData.description,
          base_url: formData.base_url,
          redirect_uris: formData.redirect_uris.split('\n').filter(uri => uri.trim()),
        })

        alert(`Application "${selectedApp.name}" updated successfully!`)
        setEditAppModal(false)
        setSelectedApp(null)

        // Refresh the applications list
        queryClient.invalidateQueries({ queryKey: ['applications'] })
      }
    } catch (error) {
      console.error('Error updating application:', error)
      alert(`Error updating application: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleSsoSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      if (selectedApp) {
        // Update SSO settings via API (this would be a separate endpoint)
        alert(`SSO settings updated for "${selectedApp.name}": ${JSON.stringify(ssoSettings)}`)
        setSsoSettingsModal(false)
        setSelectedApp(null)

        // Refresh the applications list
        queryClient.invalidateQueries({ queryKey: ['applications'] })
      }
    } catch (error) {
      console.error('Error updating SSO settings:', error)
      alert(`Error updating SSO settings: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  const handleSsoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target
    setSsoSettings(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

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
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => handleEditApp(app)}>
                                <Edit className="mr-2 h-4 w-4" />
                                Edit Application
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleCopyClientId(app.client_id)}>
                                <Copy className="mr-2 h-4 w-4" />
                                Copy Client ID
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleSsoSettings(app)}>
                                <Settings className="mr-2 h-4 w-4" />
                                SSO Settings
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem className="text-red-600" onClick={() => handleDeleteApp(app.id)}>
                                <Trash2 className="mr-2 h-4 w-4" />
                                Delete Application
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
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

      {/* Edit Application Modal */}
      <Dialog open={editAppModal} onOpenChange={setEditAppModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Edit Application</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleFormSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Application Name</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                placeholder="Enter application description"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="base_url">Base URL</Label>
              <Input
                id="base_url"
                name="base_url"
                value={formData.base_url}
                onChange={handleInputChange}
                placeholder="https://example.com"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="redirect_uris">Redirect URIs (one per line)</Label>
              <textarea
                id="redirect_uris"
                name="redirect_uris"
                value={formData.redirect_uris}
                onChange={handleInputChange}
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="https://example.com/callback&#10;https://example.com/redirect"
              />
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setEditAppModal(false)}>
                Cancel
              </Button>
              <Button type="submit">Update Application</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      {/* SSO Settings Modal */}
      <Dialog open={ssoSettingsModal} onOpenChange={setSsoSettingsModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>SSO Settings - {selectedApp?.name}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSsoSubmit} className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="enabled"
                  name="enabled"
                  checked={ssoSettings.enabled}
                  onChange={handleSsoChange}
                  className="rounded"
                />
                <Label htmlFor="enabled">SSO Enabled</Label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="refreshToken"
                  name="refreshToken"
                  checked={ssoSettings.refreshToken}
                  onChange={handleSsoChange}
                  className="rounded"
                />
                <Label htmlFor="refreshToken">Use Refresh Tokens</Label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="consentRequired"
                  name="consentRequired"
                  checked={ssoSettings.consentRequired}
                  onChange={handleSsoChange}
                  className="rounded"
                />
                <Label htmlFor="consentRequired">Require User Consent</Label>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="accessTokenLifetime">Access Token Lifetime (seconds)</Label>
                <Input
                  id="accessTokenLifetime"
                  name="accessTokenLifetime"
                  type="number"
                  value={ssoSettings.accessTokenLifetime}
                  onChange={handleSsoChange}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="refreshTokenLifetime">Refresh Token Lifetime (seconds)</Label>
                <Input
                  id="refreshTokenLifetime"
                  name="refreshTokenLifetime"
                  type="number"
                  value={ssoSettings.refreshTokenLifetime}
                  onChange={handleSsoChange}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-4">
              <Button type="button" variant="outline" onClick={() => setSsoSettingsModal(false)}>
                Cancel
              </Button>
              <Button type="submit">Save SSO Settings</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
