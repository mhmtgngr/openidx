import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { HelpCircle } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { QueryError } from './query-error'
import { api } from '../lib/api'

// "Why can this person reach that?" — GET /api/v1/access/decisions/explain
// answers with the decision every enforcement point takes for this user on
// an application: the grant that lets them in (or none), every condition
// the resource sets with what was observed, the reasons, and the same one
// sentence the audit log carries. Situation conditions (device, risk,
// country) are not known here and show as unjudged.

export interface ExplainCondition {
  name: string
  required: string
  observed: string
  satisfied: boolean
  judged: boolean
}

export interface ExplainDecision {
  application_id: string
  application_name: string
  kind: string
  enforced: boolean
  allowed: boolean
  would_deny: boolean
  grant: string
  conditions: ExplainCondition[] | null
  reasons: string[] | null
  step_up_required: boolean
}

export interface ExplainResponse {
  decision: ExplainDecision
  explain: string
}

interface AppOption {
  id: string
  name: string
}

const asArray = <T,>(v: unknown): T[] =>
  Array.isArray(v)
    ? (v as T[])
    : Array.isArray((v as { data?: unknown })?.data)
      ? ((v as { data: T[] }).data)
      : Array.isArray((v as { items?: unknown })?.items)
        ? ((v as { items: T[] }).items)
        : []

export function WhyAccessPanel({ userId, initialAppId = '' }: { userId: string; initialAppId?: string }) {
  const { t } = useTranslation()
  const [appId, setAppId] = useState(initialAppId)

  const apps = useQuery({
    queryKey: ['apps-for-explain'],
    queryFn: async () => asArray<AppOption>(await api.get<unknown>('/api/v1/applications')),
  })
  const explain = useQuery({
    queryKey: ['access-explain', userId, appId],
    queryFn: () =>
      api.get<ExplainResponse>(
        `/api/v1/access/decisions/explain?user=${encodeURIComponent(userId)}&app=${encodeURIComponent(appId)}`,
      ),
    enabled: !!appId,
  })

  const d = explain.data?.decision
  const verdictKey = !d ? '' : d.enforced ? (d.allowed ? 'allowed' : 'denied') : d.would_deny ? 'wouldDeny' : 'allowed'

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <HelpCircle className="h-5 w-5" />
          {t('pages.userAccess360.why.title')}
        </CardTitle>
        <CardDescription>{t('pages.userAccess360.why.subtitle')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="max-w-md">
          <Select value={appId} onValueChange={setAppId}>
            <SelectTrigger aria-label={t('pages.userAccess360.why.pickApp')} data-testid="why-app-picker">
              <SelectValue placeholder={t('pages.userAccess360.why.pickApp')} />
            </SelectTrigger>
            <SelectContent>
              {(apps.data ?? []).map((a) => (
                <SelectItem key={a.id} value={a.id}>
                  {a.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {explain.isError ? (
          <QueryError error={explain.error} resource={t('pages.userAccess360.why.resource')} />
        ) : d ? (
          <div className="space-y-3" data-testid="why-decision">
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={verdictKey === 'allowed' ? 'default' : verdictKey === 'denied' ? 'destructive' : 'secondary'}
                data-testid="why-verdict"
              >
                {t(`pages.userAccess360.why.verdict.${verdictKey}`)}
              </Badge>
              <Badge variant="outline">
                {d.enforced ? t('pages.userAccess360.why.enforced') : t('pages.userAccess360.why.observe')}
              </Badge>
              {d.step_up_required && <Badge variant="secondary">{t('pages.userAccess360.why.stepUp')}</Badge>}
            </div>
            <p className="text-sm">
              <span className="text-muted-foreground">{t('pages.userAccess360.why.grant')}: </span>
              <span className="font-mono" data-testid="why-grant">
                {d.grant || t('pages.userAccess360.why.noGrant')}
              </span>
            </p>
            {(d.conditions?.length ?? 0) > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.userAccess360.why.columns.condition')}</TableHead>
                    <TableHead>{t('pages.userAccess360.why.columns.required')}</TableHead>
                    <TableHead>{t('pages.userAccess360.why.columns.observed')}</TableHead>
                    <TableHead>{t('pages.userAccess360.why.columns.result')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.conditions!.map((c) => (
                    <TableRow key={c.name}>
                      <TableCell className="font-mono text-xs">{c.name}</TableCell>
                      <TableCell>{c.required}</TableCell>
                      <TableCell>{c.observed}</TableCell>
                      <TableCell data-testid={`why-cond-${c.name}`}>
                        {!c.judged
                          ? t('pages.userAccess360.why.unjudged')
                          : c.satisfied
                            ? t('pages.userAccess360.why.satisfied')
                            : t('pages.userAccess360.why.failed')}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {(d.reasons?.length ?? 0) > 0 && (
              <p className="text-sm text-red-600" data-testid="why-reasons">
                {t('pages.userAccess360.why.reasons')}: {d.reasons!.join(', ')}
              </p>
            )}
            <pre className="whitespace-pre-wrap rounded-md bg-muted p-3 text-xs" data-testid="why-explain">
              {explain.data?.explain}
            </pre>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">{t('pages.userAccess360.why.hint')}</p>
        )}
      </CardContent>
    </Card>
  )
}
