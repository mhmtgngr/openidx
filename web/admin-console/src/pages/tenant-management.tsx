import { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Building2, Palette, Settings, Globe, Plus, Trash2, CheckCircle, Copy, Save } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

interface Organization { id: string; name: string; slug: string }

interface TenantBranding {
  logo_url: string; favicon_url: string; primary_color: string; secondary_color: string
  background_color: string; background_image_url: string; login_page_title: string
  login_page_message: string; portal_title: string; custom_css: string
  custom_footer: string; powered_by_visible: boolean
}

interface TenantSettings {
  security: Record<string, unknown>
  authentication: Record<string, unknown>
  session: Record<string, unknown>
}

interface TenantDomain {
  id: string; domain: string; domain_type: string; verified: boolean; primary_domain: boolean
  verification_token?: string
}

/**
 * Seeds for a tenant that has never been branded. These are the tenant's
 * own data — its end users read them on its login page — so they are sent
 * to the API and rendered exactly as stored, in English, rather than
 * translated into whatever language the operator happens to be using.
 */
const defaultBranding: TenantBranding = {
  logo_url: '', favicon_url: '', primary_color: '#3b82f6', secondary_color: '#6366f1',
  background_color: '#f8fafc', background_image_url: '', login_page_title: 'Sign In',
  login_page_message: 'Welcome back. Please sign in to continue.',
  portal_title: 'Admin Portal', custom_css: '', custom_footer: '', powered_by_visible: true,
}

const TABS = [
  { id: 'branding', icon: Palette },
  { id: 'settings', icon: Settings },
  { id: 'domains', icon: Globe },
] as const

/** The three JSON settings groups the tenant settings API accepts. */
const SETTINGS_CATEGORIES = ['security', 'authentication', 'session'] as const

type TabId = typeof TABS[number]['id']

export function TenantManagementPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState<TabId>('branding')
  const [selectedOrgId, setSelectedOrgId] = useState('')
  const [branding, setBranding] = useState<TenantBranding>(defaultBranding)
  const [settingsJson, setSettingsJson] = useState<Record<string, string>>({})
  const [addDomainOpen, setAddDomainOpen] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [newDomainType, setNewDomainType] = useState('subdomain')

  // Backend returns a bare JSON array (with X-Total-Count), not { data: [...] };
  // reading orgsData.data left the tenant picker permanently empty.
  const { data: orgsData, isError: orgsError, error: orgsErrorObj } = useQuery({
    queryKey: ['organizations'],
    queryFn: () => api.get<Organization[]>('/api/v1/organizations'),
  })
  const orgs = useMemo(() => orgsData || [], [orgsData])

  useEffect(() => { if (orgs.length > 0 && !selectedOrgId) setSelectedOrgId(orgs[0].id) }, [orgs, selectedOrgId])

  const { data: brandingData, isLoading: brandingLoading } = useQuery({
    queryKey: ['tenant-branding', selectedOrgId],
    queryFn: () => api.get<TenantBranding>(`/api/v1/tenants/${selectedOrgId}/branding`),
    enabled: !!selectedOrgId,
  })

  useEffect(() => { if (brandingData) setBranding(brandingData) }, [brandingData])

  const { data: settingsData, isLoading: settingsLoading } = useQuery({
    queryKey: ['tenant-settings', selectedOrgId],
    queryFn: () => api.get<TenantSettings>(`/api/v1/tenants/${selectedOrgId}/settings`),
    enabled: !!selectedOrgId,
  })

  useEffect(() => {
    if (settingsData) setSettingsJson({
      security: JSON.stringify(settingsData.security, null, 2),
      authentication: JSON.stringify(settingsData.authentication, null, 2),
      session: JSON.stringify(settingsData.session, null, 2),
    })
  }, [settingsData])

  const { data: domainsData, isLoading: domainsLoading } = useQuery({
    queryKey: ['tenant-domains', selectedOrgId],
    queryFn: () => api.get<{ data: TenantDomain[] }>(`/api/v1/tenants/${selectedOrgId}/domains`),
    enabled: !!selectedOrgId,
  })
  const domains = domainsData?.data || []

  const invalidate = (key: string) => () => queryClient.invalidateQueries({ queryKey: [key, selectedOrgId] })

  const saveBrandingMutation = useMutation({
    mutationFn: (data: TenantBranding) => api.put(`/api/v1/tenants/${selectedOrgId}/branding`, data),
    onSuccess: () => {
      invalidate('tenant-branding')()
      toast({ title: t('pages.tenantManagement.toasts.brandingSaved') })
    },
    onError: () =>
      toast({
        title: t('pages.tenantManagement.toasts.brandingFailed'),
        variant: 'destructive',
      }),
  })

  const saveSettingsMutation = useMutation({
    mutationFn: ({ category, value }: { category: string; value: string }) =>
      api.put(`/api/v1/tenants/${selectedOrgId}/settings`, { category, settings: JSON.parse(value) }),
    onSuccess: () => {
      invalidate('tenant-settings')()
      toast({ title: t('pages.tenantManagement.toasts.settingsSaved') })
    },
    // The message is the JSON parser's own, so it is surfaced verbatim.
    onError: (err: Error) =>
      toast({
        title: t('pages.tenantManagement.toasts.settingsFailed'),
        description: err.message,
        variant: 'destructive',
      }),
  })

  const addDomainMutation = useMutation({
    mutationFn: (body: { domain: string; domain_type: string }) => api.post(`/api/v1/tenants/${selectedOrgId}/domains`, body),
    onSuccess: () => {
      invalidate('tenant-domains')()
      toast({ title: t('pages.tenantManagement.toasts.domainAdded') })
      setAddDomainOpen(false)
      setNewDomain('')
    },
    onError: () =>
      toast({
        title: t('pages.tenantManagement.toasts.domainAddFailed'),
        variant: 'destructive',
      }),
  })

  const verifyDomainMutation = useMutation({
    mutationFn: (domainId: string) => api.post(`/api/v1/tenants/${selectedOrgId}/domains/${domainId}/verify`, { token: '' }),
    onSuccess: () => {
      invalidate('tenant-domains')()
      toast({ title: t('pages.tenantManagement.toasts.domainVerified') })
    },
    onError: () =>
      toast({
        title: t('pages.tenantManagement.toasts.verifyFailed'),
        variant: 'destructive',
      }),
  })

  const deleteDomainMutation = useMutation({
    mutationFn: (domainId: string) => api.delete(`/api/v1/tenants/${selectedOrgId}/domains/${domainId}`),
    onSuccess: () => {
      invalidate('tenant-domains')()
      toast({ title: t('pages.tenantManagement.toasts.domainRemoved') })
    },
    onError: () =>
      toast({
        title: t('pages.tenantManagement.toasts.domainDeleteFailed'),
        variant: 'destructive',
      }),
  })

  const updateBranding = (field: keyof TenantBranding, value: string | boolean) => {
    setBranding(b => ({ ...b, [field]: value }))
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.tenantManagement.title')}</h1>
          <p className="text-muted-foreground">{t('pages.tenantManagement.subtitle')}</p>
        </div>
      </div>

      {orgsError && (
        <QueryError error={orgsErrorObj} resource={t('pages.tenantManagement.orgsResource')} />
      )}

      <div className="space-y-2">
        <label className="text-sm font-medium">{t('pages.tenantManagement.organization')}</label>
        <Select value={selectedOrgId} onValueChange={setSelectedOrgId}>
          <SelectTrigger className="w-64">
            <SelectValue placeholder={t('pages.tenantManagement.selectOrg')} />
          </SelectTrigger>
          <SelectContent>
            {orgs.map(o => <SelectItem key={o.id} value={o.id}>{o.name}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      {!selectedOrgId ? (
        <div className="flex flex-col items-center py-12 text-muted-foreground"><Building2 className="h-12 w-12 text-muted-foreground/40 mb-3" /><p>{t('pages.tenantManagement.noOrgSelected')}</p></div>
      ) : (
        <>
          <div className="flex gap-2 border-b">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-muted-foreground hover:text-foreground'
                }`}
              >
                <tab.icon className="h-4 w-4" />
                {t(`pages.tenantManagement.tabs.${tab.id}`)}
              </button>
            ))}
          </div>

          {activeTab === 'branding' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle>{t('pages.tenantManagement.branding.title')}</CardTitle>
                    <CardDescription>
                      {t('pages.tenantManagement.branding.desc')}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {brandingLoading ? (
                      <div className="flex justify-center py-8"><LoadingSpinner size="lg" /></div>
                    ) : (
                      <>
                        <div className="grid gap-4 md:grid-cols-2">
                          <div className="space-y-2">
                            <label className="text-sm font-medium">
                              {t('pages.tenantManagement.branding.logoUrl')}
                            </label>
                            {/* Asset URLs teach the format the API stores. */}
                            <Input value={branding.logo_url} onChange={e => updateBranding('logo_url', e.target.value)} placeholder="https://example.com/logo.png" />
                          </div>
                          <div className="space-y-2">
                            <label className="text-sm font-medium">
                              {t('pages.tenantManagement.branding.faviconUrl')}
                            </label>
                            <Input value={branding.favicon_url} onChange={e => updateBranding('favicon_url', e.target.value)} placeholder="https://example.com/favicon.ico" />
                          </div>
                        </div>
                        <div className="grid gap-4 md:grid-cols-3">
                          {(['primary_color', 'secondary_color', 'background_color'] as const).map(field => (
                            <div key={field} className="space-y-2">
                              <label className="text-sm font-medium">
                                {t(`pages.tenantManagement.branding.colors.${field}`)}
                              </label>
                              <div className="flex gap-2">
                                <input type="color" value={branding[field]} onChange={e => updateBranding(field, e.target.value)} className="h-10 w-14 rounded border cursor-pointer" />
                                <Input value={branding[field]} onChange={e => updateBranding(field, e.target.value)} />
                              </div>
                            </div>
                          ))}
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">
                            {t('pages.tenantManagement.branding.backgroundImageUrl')}
                          </label>
                          <Input value={branding.background_image_url} onChange={e => updateBranding('background_image_url', e.target.value)} placeholder="https://example.com/bg.jpg" />
                        </div>
                        <div className="grid gap-4 md:grid-cols-2">
                          <div className="space-y-2">
                            <label className="text-sm font-medium">
                              {t('pages.tenantManagement.branding.loginPageTitle')}
                            </label>
                            <Input value={branding.login_page_title} onChange={e => updateBranding('login_page_title', e.target.value)} />
                          </div>
                          <div className="space-y-2">
                            <label className="text-sm font-medium">
                              {t('pages.tenantManagement.branding.portalTitle')}
                            </label>
                            <Input value={branding.portal_title} onChange={e => updateBranding('portal_title', e.target.value)} />
                          </div>
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">
                            {t('pages.tenantManagement.branding.loginPageMessage')}
                          </label>
                          <textarea value={branding.login_page_message} onChange={e => updateBranding('login_page_message', e.target.value)} className="w-full border rounded-md px-3 py-2 min-h-[80px]" />
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">
                            {t('pages.tenantManagement.branding.customCss')}
                          </label>
                          <textarea value={branding.custom_css} onChange={e => updateBranding('custom_css', e.target.value)} className="w-full border rounded-md px-3 py-2 min-h-[100px] font-mono text-sm" placeholder="/* Custom CSS overrides */" />
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">
                            {t('pages.tenantManagement.branding.customFooter')}
                          </label>
                          <textarea value={branding.custom_footer} onChange={e => updateBranding('custom_footer', e.target.value)} className="w-full border rounded-md px-3 py-2 min-h-[60px]" />
                        </div>
                        <label className="flex items-center gap-2">
                          <input type="checkbox" checked={branding.powered_by_visible} onChange={e => updateBranding('powered_by_visible', e.target.checked)} className="rounded" />
                          <span className="text-sm font-medium">
                            {t('pages.tenantManagement.branding.poweredBy')}
                          </span>
                        </label>
                        <Button onClick={() => saveBrandingMutation.mutate(branding)} disabled={saveBrandingMutation.isPending}>
                          <Save className="mr-2 h-4 w-4" />
                          {saveBrandingMutation.isPending
                            ? t('pages.tenantManagement.branding.saving')
                            : t('pages.tenantManagement.branding.save')}
                        </Button>
                      </>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Live preview */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">{t('pages.tenantManagement.preview.title')}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="rounded-lg border overflow-hidden" style={{ backgroundColor: branding.background_color, backgroundImage: branding.background_image_url ? `url(${branding.background_image_url})` : undefined, backgroundSize: 'cover' }}>
                    <div className="p-6 flex flex-col items-center gap-4">
                      {branding.logo_url && (
                        <img
                          src={branding.logo_url}
                          alt={t('pages.tenantManagement.preview.logoAlt')}
                          className="h-10 object-contain"
                        />
                      )}
                      {/* Title, message and footer are the tenant's own copy,
                          shown exactly as it will appear to its users. */}
                      <h3 className="font-semibold text-sm" style={{ color: branding.primary_color }}>
                        {branding.login_page_title || defaultBranding.login_page_title}
                      </h3>
                      <p className="text-xs text-center text-muted-foreground">{branding.login_page_message}</p>
                      <div className="w-full space-y-2">
                        <div className="h-8 w-full bg-background border rounded px-2 flex items-center text-xs text-muted-foreground">
                          {t('pages.tenantManagement.preview.username')}
                        </div>
                        <div className="h-8 w-full bg-background border rounded px-2 flex items-center text-xs text-muted-foreground">
                          {t('pages.tenantManagement.preview.password')}
                        </div>
                        <div
                          className="h-8 w-full rounded text-white text-xs flex items-center justify-center font-medium"
                          style={{ backgroundColor: branding.primary_color }}
                        >
                          {t('pages.tenantManagement.preview.signIn')}
                        </div>
                      </div>
                      {branding.custom_footer && <p className="text-[10px] text-muted-foreground text-center">{branding.custom_footer}</p>}
                      {branding.powered_by_visible && <p className="text-[10px] text-muted-foreground">Powered by OpenIDX</p>}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6">
              {settingsLoading ? (
                <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
              ) : (
                SETTINGS_CATEGORIES.map(category => (
                  <Card key={category}>
                    <CardHeader>
                      <CardTitle>
                        {t(`pages.tenantManagement.settings.categories.${category}`)}
                      </CardTitle>
                      <CardDescription>
                        {t('pages.tenantManagement.settings.desc', {
                          category: t(
                            `pages.tenantManagement.settings.categories.${category}`,
                          ),
                        })}
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <textarea
                        value={settingsJson[category] || '{}'}
                        onChange={e => setSettingsJson(s => ({ ...s, [category]: e.target.value }))}
                        className="w-full border rounded-md px-3 py-2 min-h-[200px] font-mono text-sm"
                      />
                      <Button
                        onClick={() => saveSettingsMutation.mutate({ category, value: settingsJson[category] || '{}' })}
                        disabled={saveSettingsMutation.isPending}
                      >
                        <Save className="mr-2 h-4 w-4" />
                        {t('pages.tenantManagement.settings.save', {
                          category: t(
                            `pages.tenantManagement.settings.categories.${category}`,
                          ),
                        })}
                      </Button>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          )}

          {activeTab === 'domains' && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>{t('pages.tenantManagement.domains.title')}</CardTitle>
                    <CardDescription>{t('pages.tenantManagement.domains.desc')}</CardDescription>
                  </div>
                  <Button onClick={() => setAddDomainOpen(true)}>
                    <Plus className="mr-2 h-4 w-4" />
                    {t('pages.tenantManagement.domains.add')}
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {domainsLoading ? (
                  <div className="flex justify-center py-8"><LoadingSpinner size="lg" /></div>
                ) : domains.length === 0 ? (
                  <div className="flex flex-col items-center py-12 text-muted-foreground"><Globe className="h-12 w-12 text-muted-foreground/40 mb-3" /><p className="font-medium">{t('pages.tenantManagement.domains.emptyTitle')}</p><p className="text-sm">{t('pages.tenantManagement.domains.emptyHint')}</p></div>
                ) : (
                  <Table>
                    <TableHeader><TableRow>
                      <TableHead>{t('pages.tenantManagement.domains.colDomain')}</TableHead>
                      <TableHead>{t('pages.tenantManagement.domains.colType')}</TableHead>
                      <TableHead>{t('pages.tenantManagement.domains.colVerified')}</TableHead>
                      <TableHead>{t('pages.tenantManagement.domains.colPrimary')}</TableHead>
                      <TableHead>{t('pages.tenantManagement.domains.colActions')}</TableHead>
                    </TableRow></TableHeader>
                    <TableBody>
                      {domains.map(d => (
                        <TableRow key={d.id}>
                          <TableCell className="font-medium">{d.domain}</TableCell>
                          <TableCell>
                            <Badge variant="outline">
                              {t(`pages.tenantManagement.domains.types.${d.domain_type}`, {
                                defaultValue: d.domain_type,
                              })}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={d.verified ? 'default' : 'secondary'}>
                              {d.verified
                                ? t('pages.tenantManagement.domains.verified')
                                : t('pages.tenantManagement.domains.pending')}
                            </Badge>
                            {!d.verified && d.verification_token && (
                              <button
                                className="ml-2 inline-flex items-center gap-1 text-xs text-primary hover:underline"
                                onClick={() => {
                                  navigator.clipboard.writeText(d.verification_token || '')
                                  toast({ title: t('pages.tenantManagement.toasts.tokenCopied') })
                                }}
                              >
                                <Copy className="h-3 w-3" />{d.verification_token}
                              </button>
                            )}
                          </TableCell>
                          <TableCell>
                            {d.primary_domain ? (
                              <Badge variant="default">{t('pages.tenantManagement.domains.primary')}</Badge>
                            ) : (
                              '-'
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1">
                              {!d.verified && (
                                <ConfirmAction
                                  title={t('pages.tenantManagement.domains.verifyTitle')}
                                  description={t('pages.tenantManagement.domains.verifyDesc', {
                                    domain: d.domain,
                                  })}
                                  confirmLabel={t('pages.tenantManagement.domains.verifyConfirm')}
                                  onConfirm={() => verifyDomainMutation.mutateAsync(d.id)}
                                >
                                  {(open) => (
                                    <Button variant="ghost" size="sm" onClick={open}>
                                      <CheckCircle className="h-4 w-4 text-green-600" />
                                    </Button>
                                  )}
                                </ConfirmAction>
                              )}
                              <ConfirmAction
                                title={t('pages.tenantManagement.domains.deleteTitle')}
                                description={t('pages.tenantManagement.domains.deleteDesc', {
                                  domain: d.domain,
                                })}
                                destructive
                                confirmLabel={t('common.delete')}
                                onConfirm={() => deleteDomainMutation.mutateAsync(d.id)}
                              >
                                {(open) => (
                                  <Button variant="ghost" size="sm" onClick={open}>
                                    <Trash2 className="h-4 w-4 text-red-500" />
                                  </Button>
                                )}
                              </ConfirmAction>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Add Domain Dialog */}
      <Dialog open={addDomainOpen} onOpenChange={setAddDomainOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('pages.tenantManagement.domains.add')}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">
                {t('pages.tenantManagement.domains.domainLabel')}
              </label>
              {/* The sample host teaches the format the API accepts. */}
              <Input value={newDomain} onChange={e => setNewDomain(e.target.value)} placeholder="login.example.com" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">
                {t('pages.tenantManagement.domains.typeLabel')}
              </label>
              <Select value={newDomainType} onValueChange={setNewDomainType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="subdomain">
                    {t('pages.tenantManagement.domains.types.subdomain')}
                  </SelectItem>
                  <SelectItem value="custom">
                    {t('pages.tenantManagement.domains.types.custom')}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddDomainOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button disabled={!newDomain.trim() || addDomainMutation.isPending} onClick={() => addDomainMutation.mutate({ domain: newDomain.trim(), domain_type: newDomainType })}>
              {addDomainMutation.isPending
                ? t('pages.tenantManagement.domains.adding')
                : t('pages.tenantManagement.domains.add')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
