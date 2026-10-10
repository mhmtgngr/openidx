import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, AlertTriangle } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Switch } from './ui/switch'
import { LoadingSpinner } from './ui/loading-spinner'
import { useToast } from '../hooks/use-toast'
import { api } from '../lib/api'

// GET/PUT /api/v1/access/pam/policy: the organization's privileged-session
// policy (migration 229). "default" means no row exists and the secure
// defaults apply; an organization that existed before the migration has a row
// carrying its old behaviour, which is why the card warns when internal
// sessions are not recorded.
export interface PamPolicy {
  org_id: string
  max_session_hours: number
  idle_timeout_minutes: number
  require_approval_internal: boolean
  record_internal: boolean
  launch_approval_window_minutes: number
  source: 'policy' | 'default'
  updated_at?: string
  updated_by?: string
}

type Draft = Omit<PamPolicy, 'org_id' | 'source' | 'updated_at' | 'updated_by'>

const DEFAULTS: Draft = {
  max_session_hours: 8,
  idle_timeout_minutes: 0,
  require_approval_internal: false,
  record_internal: true,
  launch_approval_window_minutes: 60,
}

function draftOf(p?: PamPolicy): Draft {
  return {
    max_session_hours: p?.max_session_hours ?? DEFAULTS.max_session_hours,
    idle_timeout_minutes: p?.idle_timeout_minutes ?? DEFAULTS.idle_timeout_minutes,
    require_approval_internal: p?.require_approval_internal ?? DEFAULTS.require_approval_internal,
    record_internal: p?.record_internal ?? DEFAULTS.record_internal,
    launch_approval_window_minutes:
      p?.launch_approval_window_minutes ?? DEFAULTS.launch_approval_window_minutes,
  }
}

export function PamPolicyCard() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['pam-policy'],
    queryFn: () => api.get<PamPolicy>('/api/v1/access/pam/policy'),
  })
  // What the administrator has typed, or the server's answer until then: no
  // effect copying one into the other.
  const [edited, setEdited] = useState<Draft | null>(null)
  const draft = edited ?? draftOf(data)
  const setDraft = (f: (d: Draft) => Draft) => setEdited(f(draft))

  const save = useMutation({
    mutationFn: (d: Draft) => api.put<PamPolicy>('/api/v1/access/pam/policy', d),
    onSuccess: (resp) => {
      qc.setQueryData(['pam-policy'], resp)
      setEdited(null)
      toast({ title: t('pages.pamPolicy.saved') })
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ||
        t('pages.pamPolicy.saveFailed')
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const source = data?.source ?? 'default'
  const number = (key: keyof Draft) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value
    setDraft((d) => ({ ...d, [key]: v === '' ? 0 : Math.max(0, parseInt(v, 10) || 0) }))
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center justify-between text-base">
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" />
            {t('pages.pamPolicy.title')}
          </span>
          <Badge variant={source === 'policy' ? 'default' : 'secondary'} data-testid="pam-policy-source">
            {t(`pages.pamPolicy.source.${source}`)}
          </Badge>
        </CardTitle>
        <CardDescription>{t('pages.pamPolicy.subtitle')}</CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingSpinner />
        ) : (
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault()
              save.mutate(draft)
            }}
          >
            {!draft.record_internal && (
              <p
                role="note"
                className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-100"
              >
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {t('pages.pamPolicy.notRecordingWarning')}
              </p>
            )}
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="pam-record-internal">{t('pages.pamPolicy.recordInternal')}</Label>
              <Switch
                id="pam-record-internal"
                checked={draft.record_internal}
                onCheckedChange={(v) => setDraft((d) => ({ ...d, record_internal: v }))}
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="pam-require-approval">{t('pages.pamPolicy.requireApprovalInternal')}</Label>
              <Switch
                id="pam-require-approval"
                checked={draft.require_approval_internal}
                onCheckedChange={(v) => setDraft((d) => ({ ...d, require_approval_internal: v }))}
              />
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1">
                <Label htmlFor="pam-max-hours">{t('pages.pamPolicy.maxSessionHours')}</Label>
                <Input
                  id="pam-max-hours"
                  type="number"
                  min={0}
                  max={168}
                  value={draft.max_session_hours}
                  onChange={number('max_session_hours')}
                />
                <p className="text-xs text-muted-foreground">{t('pages.pamPolicy.maxSessionHoursHint')}</p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="pam-window">{t('pages.pamPolicy.launchApprovalWindowMinutes')}</Label>
                <Input
                  id="pam-window"
                  type="number"
                  min={5}
                  max={1440}
                  value={draft.launch_approval_window_minutes}
                  onChange={number('launch_approval_window_minutes')}
                />
                <p className="text-xs text-muted-foreground">{t('pages.pamPolicy.launchApprovalWindowHint')}</p>
              </div>
              <div className="space-y-1">
                <Label htmlFor="pam-idle">{t('pages.pamPolicy.idleTimeoutMinutes')}</Label>
                <Input
                  id="pam-idle"
                  type="number"
                  min={0}
                  max={1440}
                  value={draft.idle_timeout_minutes}
                  onChange={number('idle_timeout_minutes')}
                />
                <p className="text-xs text-muted-foreground">{t('pages.pamPolicy.idleTimeoutHint')}</p>
              </div>
            </div>
            <div className="flex justify-end">
              <Button type="submit" size="sm" disabled={save.isPending}>
                {t('pages.pamPolicy.save')}
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  )
}
