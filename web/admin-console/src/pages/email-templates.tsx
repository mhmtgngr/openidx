import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { SelectableRow } from '../components/selectable-row'
import { Mail, Eye, RotateCcw, Save, Palette } from 'lucide-react'

interface EmailTemplate {
  id: string
  name: string
  slug: string
  subject: string
  html_body: string
  text_body: string
  category: string
  variables: string[]
  enabled: boolean
  updated_by: string | null
  created_at: string
  updated_at: string
}

interface EmailBranding {
  id?: string
  org_id?: string
  logo_url: string
  primary_color: string
  accent_color: string
  header_text: string
  footer_text: string
}

export function EmailTemplatesPage() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [editSubject, setEditSubject] = useState('')
  const [editHtml, setEditHtml] = useState('')
  const [editText, setEditText] = useState('')
  const [previewHtml, setPreviewHtml] = useState('')
  const [showBranding, setShowBranding] = useState(false)
  const [branding, setBranding] = useState<EmailBranding>({
    logo_url: '', primary_color: '#1e40af', accent_color: '#3b82f6', header_text: '', footer_text: '',
  })

  const { data: templatesData, isLoading, isError, error } = useQuery({
    queryKey: ['email-templates'],
    queryFn: () => api.get<{ data: EmailTemplate[] }>('/api/v1/email-templates'),
  })

  const { data: brandingData } = useQuery({
    queryKey: ['email-branding'],
    queryFn: () => api.get<EmailBranding>('/api/v1/email-branding'),
  })

  // Sync branding data when loaded
  if (brandingData && brandingData.primary_color && branding.primary_color === '#1e40af' && brandingData.primary_color !== '#1e40af') {
    setBranding(brandingData)
  }

  const updateMutation = useMutation({
    mutationFn: ({ id, ...data }: { id: string; subject: string; html_body: string; text_body: string }) =>
      api.put(`/api/v1/email-templates/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-templates'] })
    },
  })

  const resetMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/email-templates/${id}/reset`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['email-templates'] })
      setSelectedId(null)
    },
  })

  const brandingMutation = useMutation({
    mutationFn: (data: EmailBranding) => api.put('/api/v1/email-branding', data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['email-branding'] }),
  })

  const handleSelectTemplate = (tmpl: EmailTemplate) => {
    setSelectedId(tmpl.id)
    setEditSubject(tmpl.subject)
    setEditHtml(tmpl.html_body)
    setEditText(tmpl.text_body || '')
    setPreviewHtml('')
  }

  const handleSave = () => {
    if (!selectedId) return
    updateMutation.mutate({ id: selectedId, subject: editSubject, html_body: editHtml, text_body: editText })
  }

  const handlePreview = async () => {
    if (!selectedId) return
    const result = await api.post<{ html: string }>(`/api/v1/email-templates/${selectedId}/preview`, {})
    setPreviewHtml(result.html)
  }

  if (isLoading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  if (isError) return <QueryError error={error} resource={t('pages.emailTemplates.resource')} />

  const templates = templatesData?.data || []
  const selectedTemplate = templates.find(tmpl => tmpl.id === selectedId)

  // Group by category
  const grouped: Record<string, EmailTemplate[]> = {}
  templates.forEach(tmpl => {
    const cat = tmpl.category || 'general'
    if (!grouped[cat]) grouped[cat] = []
    grouped[cat].push(tmpl)
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('nav.items.emailTemplates')}</h1>
          <p className="text-muted-foreground">{t('pages.emailTemplates.subtitle')}</p>
        </div>
        <Button variant="outline" onClick={() => setShowBranding(!showBranding)}>
          <Palette className="h-4 w-4 mr-2" />
          {showBranding
            ? t('pages.emailTemplates.brandingHide')
            : t('pages.emailTemplates.brandingToggle')}
        </Button>
      </div>

      {/* Branding Settings */}
      {showBranding && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Palette className="h-5 w-5" />
              {t('pages.emailTemplates.branding.title')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* The two placeholders below are samples of what goes in the
                field — a URL and the product name — so they stay as they are. */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">
                  {t('pages.emailTemplates.branding.logoUrl')}
                </label>
                <input className="w-full border rounded px-3 py-2 mt-1 text-sm" placeholder="https://example.com/logo.png"
                  value={branding.logo_url} onChange={e => setBranding({ ...branding, logo_url: e.target.value })} />
              </div>
              <div>
                <label className="text-sm font-medium">
                  {t('pages.emailTemplates.branding.headerText')}
                </label>
                <input className="w-full border rounded px-3 py-2 mt-1 text-sm" placeholder="OpenIDX"
                  value={branding.header_text} onChange={e => setBranding({ ...branding, header_text: e.target.value })} />
              </div>
              <div>
                <label id="email-templates-primary-color-label" className="text-sm font-medium">
                  {t('pages.emailTemplates.branding.primaryColor')}
                </label>
                <div className="flex gap-2 mt-1">
                  <input aria-labelledby="email-templates-primary-color-label" type="color" value={branding.primary_color} onChange={e => setBranding({ ...branding, primary_color: e.target.value })} />
                  <input aria-labelledby="email-templates-primary-color-label" className="flex-1 border rounded px-3 py-2 text-sm" value={branding.primary_color}
                    onChange={e => setBranding({ ...branding, primary_color: e.target.value })} />
                </div>
              </div>
              <div>
                <label id="email-templates-accent-color-label" className="text-sm font-medium">
                  {t('pages.emailTemplates.branding.accentColor')}
                </label>
                <div className="flex gap-2 mt-1">
                  <input aria-labelledby="email-templates-accent-color-label" type="color" value={branding.accent_color} onChange={e => setBranding({ ...branding, accent_color: e.target.value })} />
                  <input aria-labelledby="email-templates-accent-color-label" className="flex-1 border rounded px-3 py-2 text-sm" value={branding.accent_color}
                    onChange={e => setBranding({ ...branding, accent_color: e.target.value })} />
                </div>
              </div>
            </div>
            <div>
              <label htmlFor="email-templates-footer-text" className="text-sm font-medium">
                {t('pages.emailTemplates.branding.footerText')}
              </label>
              <textarea id="email-templates-footer-text" className="w-full border rounded px-3 py-2 mt-1 text-sm h-16"
                value={branding.footer_text} onChange={e => setBranding({ ...branding, footer_text: e.target.value })} />
            </div>
            <Button onClick={() => brandingMutation.mutate(branding)} disabled={brandingMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {brandingMutation.isPending
                ? t('pages.emailTemplates.branding.saving')
                : t('pages.emailTemplates.branding.save')}
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Template List */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Mail className="h-5 w-5" />
              {t('pages.emailTemplates.list.title')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {Object.entries(grouped).map(([cat, tmpls]) => (
              <div key={cat} className="mb-4">
                <p className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                  {t(`pages.emailTemplates.categories.${cat}`, { defaultValue: cat })}
                </p>
                <div className="space-y-1">
                  {tmpls.map(tmpl => (
                    <SelectableRow
                      key={tmpl.id}
                      aria-pressed={selectedId === tmpl.id}
                      className={`p-2 rounded text-sm ${selectedId === tmpl.id ? 'bg-blue-50 border border-blue-200 dark:bg-blue-950/30 dark:border-blue-800' : 'hover:bg-muted'}`}
                      onSelect={() => handleSelectTemplate(tmpl)}>
                      <div className="flex items-center justify-between">
                        {/* The template's own name and slug. */}
                        <span className="font-medium">{tmpl.name}</span>
                        <Badge variant={tmpl.enabled ? 'default' : 'secondary'} className="text-xs">
                          {tmpl.enabled
                            ? t('pages.emailTemplates.list.active')
                            : t('pages.emailTemplates.list.disabled')}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{tmpl.slug}</p>
                    </SelectableRow>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Template Editor */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>
                {selectedTemplate
                  ? t('pages.emailTemplates.editor.edit', { name: selectedTemplate.name })
                  : t('pages.emailTemplates.editor.none')}
              </span>
              {selectedTemplate && (
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={handlePreview}>
                    <Eye className="h-3 w-3 mr-1" />
                    {t('pages.emailTemplates.editor.preview')}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => resetMutation.mutate(selectedId!)}>
                    <RotateCcw className="h-3 w-3 mr-1" />
                    {t('pages.emailTemplates.editor.reset')}
                  </Button>
                  <Button size="sm" onClick={handleSave} disabled={updateMutation.isPending}>
                    <Save className="h-3 w-3 mr-1" />
                    {updateMutation.isPending
                      ? t('pages.emailTemplates.editor.saving')
                      : t('pages.emailTemplates.editor.save')}
                  </Button>
                </div>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {selectedTemplate ? (
              <div className="space-y-4">
                <div>
                  <label htmlFor="email-templates-subject" className="text-sm font-medium">
                    {t('pages.emailTemplates.editor.subject')}
                  </label>
                  <input id="email-templates-subject" className="w-full border rounded px-3 py-2 mt-1 text-sm"
                    value={editSubject} onChange={e => setEditSubject(e.target.value)} />
                </div>

                {selectedTemplate.variables?.length > 0 && (
                  <div>
                    <label className="text-sm font-medium">
                      {t('pages.emailTemplates.editor.variables')}
                    </label>
                    {/* Go template syntax the mail renderer parses. */}
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedTemplate.variables.map(v => (
                        <Badge key={v} variant="outline" className="text-xs cursor-pointer hover:bg-blue-50"
                          onClick={() => setEditHtml(editHtml + `{{.${v}}}`)}>
                          {'{{.'}{v}{'}}'}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <label htmlFor="email-templates-html-body" className="text-sm font-medium">
                    {t('pages.emailTemplates.editor.htmlBody')}
                  </label>
                  <textarea id="email-templates-html-body" className="w-full border rounded px-3 py-2 mt-1 text-sm font-mono h-48"
                    value={editHtml} onChange={e => setEditHtml(e.target.value)} />
                </div>

                <div>
                  <label htmlFor="email-templates-text-body" className="text-sm font-medium">
                    {t('pages.emailTemplates.editor.textBody')}
                  </label>
                  <textarea id="email-templates-text-body" className="w-full border rounded px-3 py-2 mt-1 text-sm font-mono h-24"
                    value={editText} onChange={e => setEditText(e.target.value)} />
                </div>

                {/* Preview */}
                {previewHtml && (
                  <div>
                    <label className="text-sm font-medium">
                      {t('pages.emailTemplates.editor.previewLabel')}
                    </label>
                    <div className="border rounded p-4 mt-1 bg-background" dangerouslySetInnerHTML={{ __html: previewHtml }} />
                  </div>
                )}
              </div>
            ) : (
              <div className="py-12 text-center text-muted-foreground">
                <Mail className="h-12 w-12 mx-auto mb-3 text-muted-foreground" />
                <p>{t('pages.emailTemplates.editor.empty')}</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
