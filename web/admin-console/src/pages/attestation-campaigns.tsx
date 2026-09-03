import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { useState } from 'react'
import { api } from '../lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { QueryError } from '../components/query-error'
import { SelectableRow } from '../components/selectable-row'
import { ClipboardCheck, Plus, Rocket, CheckCircle, X, ArrowRight, BarChart3 } from 'lucide-react'
import { ConfirmAction } from '../components/confirm-action'
import { RelatedLinks } from '../components/related-links'

interface AttestationCampaign {
  id: string
  name: string
  description: string
  campaign_type: string
  scope: Record<string, unknown>
  reviewer_strategy: string
  status: string
  due_date: string | null
  escalation_after_days: number
  auto_revoke_on_expiry: boolean
  created_at: string
  completed_at: string | null
  total_items: number
  certified_count: number
  revoked_count: number
  pending_count: number
}

interface AttestationItem {
  id: string
  campaign_id: string
  reviewer_id: string | null
  reviewer_name: string
  user_id: string | null
  user_name: string
  resource_type: string
  resource_id: string | null
  resource_name: string
  decision: string
  delegated_to: string | null
  comments: string
  decided_at: string | null
  created_at: string
}

// Campaign-type labels resolve through i18n; keys pinned in i18n.test.ts.
const CAMPAIGN_TYPES = [
  'manager_review',
  'application_access',
  'role_certification',
  'entitlement_review',
] as const

const statusColors: Record<string, string> = {
  draft: 'bg-muted text-foreground',
  active: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  expired: 'bg-red-100 text-red-800',
}

const decisionColors: Record<string, string> = {
  pending: 'bg-yellow-100 text-yellow-800',
  certified: 'bg-green-100 text-green-800',
  revoked: 'bg-red-100 text-red-800',
  delegated: 'bg-purple-100 text-purple-800',
}

export function AttestationCampaignsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [selectedCampaign, setSelectedCampaign] = useState<string | null>(null)

  // Form state
  const [formName, setFormName] = useState('')
  const [formDesc, setFormDesc] = useState('')
  const [formType, setFormType] = useState('role_certification')
  const [formStrategy, setFormStrategy] = useState('manager')
  const [formEscalation, setFormEscalation] = useState(14)
  const [formAutoRevoke, setFormAutoRevoke] = useState(false)

  const { data: campaignsData, isLoading, isError, error } = useQuery({
    queryKey: ['attestation-campaigns'],
    queryFn: async () => {
      const res = await api.get<{ data: AttestationCampaign[] }>('/api/v1/attestation-campaigns')
      return {
        data: (res?.data ?? []).map((c): AttestationCampaign => ({
          ...c,
          name: c?.name ?? '',
          description: c?.description ?? '',
          campaign_type: c?.campaign_type ?? '',
          status: c?.status ?? '',
          total_items: c?.total_items ?? 0,
          certified_count: c?.certified_count ?? 0,
          revoked_count: c?.revoked_count ?? 0,
          pending_count: c?.pending_count ?? 0,
        })),
      }
    },
  })

  const { data: itemsData } = useQuery({
    queryKey: ['attestation-items', selectedCampaign],
    queryFn: async () => {
      const res = await api.get<{ data: AttestationItem[] }>(`/api/v1/attestation-campaigns/${selectedCampaign}/items`)
      return {
        data: (res?.data ?? []).map((item): AttestationItem => ({
          ...item,
          user_name: item?.user_name ?? '',
          resource_type: item?.resource_type ?? '',
          resource_name: item?.resource_name ?? '',
          reviewer_name: item?.reviewer_name ?? '',
          decision: item?.decision ?? '',
        })),
      }
    },
    enabled: !!selectedCampaign,
  })

  const { data: progressData } = useQuery({
    queryKey: ['attestation-progress', selectedCampaign],
    queryFn: async () => {
      const res = await api.get<{ total: number; certified: number; revoked: number; pending: number; delegated: number; completion_pct: number }>(
        `/api/v1/attestation-campaigns/${selectedCampaign}/progress`)
      return {
        total: res?.total ?? 0,
        certified: res?.certified ?? 0,
        revoked: res?.revoked ?? 0,
        pending: res?.pending ?? 0,
        delegated: res?.delegated ?? 0,
        completion_pct: res?.completion_pct ?? 0,
      }
    },
    enabled: !!selectedCampaign,
    refetchInterval: 5000,
  })

  const createMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/api/v1/attestation-campaigns', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attestation-campaigns'] })
      setShowCreate(false)
      setFormName('')
      setFormDesc('')
    },
  })

  const launchMutation = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/attestation-campaigns/${id}/launch`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attestation-campaigns'] })
      queryClient.invalidateQueries({ queryKey: ['attestation-items'] })
    },
  })

  const decideMutation = useMutation({
    mutationFn: ({ campaignId, itemId, decision, comments }: { campaignId: string; itemId: string; decision: string; comments: string }) =>
      api.post(`/api/v1/attestation-campaigns/${campaignId}/items/${itemId}/decide`, { decision, comments }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attestation-items'] })
      queryClient.invalidateQueries({ queryKey: ['attestation-progress'] })
      queryClient.invalidateQueries({ queryKey: ['attestation-campaigns'] })
    },
  })

  const handleCreate = () => {
    createMutation.mutate({
      name: formName, description: formDesc, campaign_type: formType,
      reviewer_strategy: formStrategy, escalation_after_days: formEscalation,
      auto_revoke_on_expiry: formAutoRevoke,
    })
  }

  if (isLoading) return <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
  if (isError) return <QueryError error={error} resource={t('pages.attestation.resourceName')} />

  const campaigns = campaignsData?.data || []
  const items = itemsData?.data || []
  const progress = progressData

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{t('pages.attestation.title')}</h1>
          <p className="text-muted-foreground">{t('pages.attestation.subtitle')}</p>
        </div>
        <Button onClick={() => setShowCreate(!showCreate)}>
          <Plus className="h-4 w-4 mr-2" />{showCreate ? t('common.cancel') : t('pages.attestation.newCampaign')}
        </Button>
      </div>

      <RelatedLinks
        links={[
          { to: '/access-reviews', label: t('nav.items.accessReviews') },
          { to: '/certification-campaigns', label: t('nav.items.certCampaigns') },
        ]}
      />

      {/* Create Form */}
      {showCreate && (
        <Card>
          <CardHeader><CardTitle>{t('pages.attestation.createForm.title')}</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">{t('pages.attestation.createForm.name')}</label>
                <input className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formName} onChange={e => setFormName(e.target.value)} />
              </div>
              <div>
                <label className="text-sm font-medium">{t('pages.attestation.createForm.type')}</label>
                <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formType} onChange={e => setFormType(e.target.value)}>
                  {CAMPAIGN_TYPES.map((k) => <option key={k} value={k}>{t(`pages.attestation.types.${k}`)}</option>)}
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">{t('pages.attestation.createForm.strategy')}</label>
                <select className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formStrategy} onChange={e => setFormStrategy(e.target.value)}>
                  <option value="manager">{t('pages.attestation.createForm.strategyManager')}</option>
                  <option value="owner">{t('pages.attestation.createForm.strategyOwner')}</option>
                  <option value="specific_user">{t('pages.attestation.createForm.strategySpecificUser')}</option>
                </select>
              </div>
              <div>
                <label className="text-sm font-medium">{t('pages.attestation.createForm.escalation')}</label>
                <input type="number" className="w-full border rounded px-3 py-2 mt-1 text-sm" value={formEscalation} onChange={e => setFormEscalation(Number(e.target.value))} />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.attestation.createForm.description')}</label>
              <textarea className="w-full border rounded px-3 py-2 mt-1 text-sm h-16" value={formDesc} onChange={e => setFormDesc(e.target.value)} />
            </div>
            <div className="flex items-center gap-2">
              <input type="checkbox" id="autoRevoke" checked={formAutoRevoke} onChange={e => setFormAutoRevoke(e.target.checked)} />
              <label htmlFor="autoRevoke" className="text-sm">{t('pages.attestation.createForm.autoRevoke')}</label>
            </div>
            <Button onClick={handleCreate} disabled={!formName || createMutation.isPending}>
              {createMutation.isPending ? t('pages.attestation.createForm.creating') : t('pages.attestation.createForm.create')}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Campaign List */}
      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><ClipboardCheck className="h-5 w-5" />{t('pages.attestation.listTitle', { n: campaigns.length })}</CardTitle></CardHeader>
        <CardContent>
          <div className="divide-y">
            {campaigns.map(c => {
              const pct = c.total_items > 0 ? ((c.certified_count + c.revoked_count) / c.total_items * 100) : 0
              return (
                <div key={c.id} className="py-3">
                  <div className="flex items-center justify-between">
                    <SelectableRow
                      className="flex-1"
                      aria-expanded={selectedCampaign === c.id}
                      onSelect={() => setSelectedCampaign(selectedCampaign === c.id ? null : c.id)}>
                      <div className="flex items-center gap-2">
                        <p className="font-medium text-sm">{c.name}</p>
                        <Badge variant="outline">{(CAMPAIGN_TYPES as readonly string[]).includes(c.campaign_type) ? t(`pages.attestation.types.${c.campaign_type}`) : c.campaign_type}</Badge>
                        <Badge className={statusColors[c.status] || ''}>{c.status}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{c.description}</p>
                      {c.total_items > 0 && (
                        <div className="flex items-center gap-3 mt-2">
                          <div className="flex-1 h-2 bg-muted rounded-full max-w-xs">
                            <div className="h-2 bg-green-500 rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-muted-foreground">{t('pages.attestation.percentComplete', { n: pct.toFixed(0) })}</span>
                          <span className="text-xs text-green-600">{t('pages.attestation.certifiedCount', { n: c.certified_count })}</span>
                          <span className="text-xs text-red-600">{t('pages.attestation.revokedCount', { n: c.revoked_count })}</span>
                          <span className="text-xs text-yellow-600">{t('pages.attestation.pendingCount', { n: c.pending_count })}</span>
                        </div>
                      )}
                    </SelectableRow>
                    <div className="flex gap-2 ml-4">
                      {c.status === 'draft' && (
                        <Button size="sm" onClick={() => launchMutation.mutate(c.id)} disabled={launchMutation.isPending}>
                          <Rocket className="h-3 w-3 mr-1" />{t('pages.attestation.launch')}
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
            {campaigns.length === 0 && <p className="py-8 text-center text-muted-foreground">{t('pages.attestation.empty')}</p>}
          </div>
        </CardContent>
      </Card>

      {/* Campaign Detail */}
      {selectedCampaign && progress && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2"><BarChart3 className="h-5 w-5" />{t('pages.attestation.progress.title')}</span>
              <Button variant="ghost" size="sm" onClick={() => setSelectedCampaign(null)}><X className="h-4 w-4" /></Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-5 gap-4 mb-6">
              <div className="text-center">
                <p className="text-2xl font-bold">{progress.total}</p>
                <p className="text-xs text-muted-foreground">{t('pages.attestation.progress.total')}</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-green-600">{progress.certified}</p>
                <p className="text-xs text-muted-foreground">{t('pages.attestation.progress.certified')}</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-red-600">{progress.revoked}</p>
                <p className="text-xs text-muted-foreground">{t('pages.attestation.progress.revoked')}</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-yellow-600">{progress.pending}</p>
                <p className="text-xs text-muted-foreground">{t('pages.attestation.progress.pending')}</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-purple-600">{progress.delegated}</p>
                <p className="text-xs text-muted-foreground">{t('pages.attestation.progress.delegated')}</p>
              </div>
            </div>

            {/* Items table */}
            <div className="divide-y max-h-96 overflow-y-auto">
              {items.map(item => (
                <div key={item.id} className="py-2 flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{item.user_name}</span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground" />
                      <span className="text-sm">{item.resource_name}</span>
                      <Badge variant="outline" className="text-xs">{item.resource_type}</Badge>
                    </div>
                    {item.reviewer_name && <p className="text-xs text-muted-foreground">{t('pages.attestation.reviewer', { name: item.reviewer_name })}</p>}
                  </div>
                  <div className="flex items-center gap-2">
                    {item.decision === 'pending' ? (
                      <>
                        <Button size="sm" variant="outline"
                          onClick={() => decideMutation.mutate({ campaignId: selectedCampaign, itemId: item.id, decision: 'certified', comments: '' })}>
                          <CheckCircle className="h-3 w-3 mr-1" />{t('pages.attestation.certify')}
                        </Button>
                        <ConfirmAction
                          title={t('pages.attestation.confirmRevoke.title')}
                          description={t('pages.attestation.confirmRevoke.description', { user: item.user_name, resource: item.resource_name })}
                          destructive
                          requireReason
                          confirmLabel={t('pages.attestation.revoke')}
                          onConfirm={(reason) => decideMutation.mutateAsync({ campaignId: selectedCampaign, itemId: item.id, decision: 'revoked', comments: reason! })}
                        >
                          {(open) => (
                            <Button size="sm" variant="outline" onClick={open}>
                              <X className="h-3 w-3 mr-1" />{t('pages.attestation.revoke')}
                            </Button>
                          )}
                        </ConfirmAction>
                      </>
                    ) : (
                      <Badge className={decisionColors[item.decision] || ''}>{item.decision}</Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
