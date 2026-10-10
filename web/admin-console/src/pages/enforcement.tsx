import { useTranslation } from 'react-i18next'
import { ShieldCheck, ShieldAlert, Copy } from 'lucide-react'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { QueryError } from '../components/query-error'
import { useToast } from '../hooks/use-toast'
import { useEnforcementPosture, type EnforcementGate } from '../lib/enforcement'

// Security → Enforcement: the page an administrator reads before switching a
// control from observe to enforce. Every row is one control production
// requires; "would deny (7d)" is how often its observe mode recorded a refusal
// it did not carry out. The env lines at the bottom are what closes the open
// ones. docs/runbooks/enforce-rollout.md is the procedure around this page.

function modeVariant(mode: string): 'default' | 'secondary' | 'destructive' | 'outline' {
  switch (mode) {
    case 'enforce':
      return 'default'
    case 'observe':
      return 'secondary'
    default:
      return 'destructive'
  }
}

function GateRow({ gate }: { gate: EnforcementGate }) {
  const { t } = useTranslation()
  return (
    <TableRow>
      <TableCell className="align-top font-mono text-xs">{gate.name}</TableCell>
      <TableCell className="align-top">
        <Badge variant={modeVariant(gate.mode)} data-testid={`mode-${gate.name}`}>
          {t(`pages.enforcement.mode.${gate.mode}`, { defaultValue: gate.mode })}
        </Badge>
      </TableCell>
      <TableCell className="align-top text-sm text-muted-foreground">
        {gate.enforcing ? t('pages.enforcement.enforcingMeaning') : gate.meaning}
      </TableCell>
      <TableCell className="align-top text-right tabular-nums">
        {gate.observe_action ? gate.would_deny_7d : <span className="text-muted-foreground">—</span>}
      </TableCell>
    </TableRow>
  )
}

export function EnforcementPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { data, isLoading, isError, error } = useEnforcementPosture()

  const copyEnv = async () => {
    if (!data) return
    try {
      await navigator.clipboard.writeText(data.env_lines.join('\n') + '\n')
      toast({ title: t('pages.enforcement.copied') })
    } catch {
      toast({ title: t('pages.enforcement.copyFailed'), variant: 'destructive' })
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('pages.enforcement.title')}</h1>
        <p className="text-muted-foreground">{t('pages.enforcement.subtitle')}</p>
      </div>

      {isError ? (
        <QueryError error={error} resource={t('pages.enforcement.resource')} />
      ) : isLoading || !data ? (
        <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
      ) : (
        <>
          <Card>
            <CardHeader className="flex flex-row items-center gap-3 space-y-0">
              {data.fully_enforcing ? (
                <ShieldCheck className="h-6 w-6 text-green-600" />
              ) : (
                <ShieldAlert className="h-6 w-6 text-amber-600" />
              )}
              <div>
                <CardTitle>
                  {data.fully_enforcing
                    ? t('pages.enforcement.status.enforcing')
                    : t('pages.enforcement.status.open', {
                        count: data.gates.filter((g) => !g.enforcing).length,
                      })}
                </CardTitle>
                <CardDescription>
                  {t('pages.enforcement.environment', { env: data.environment })}
                  {data.window_status ? ` · ${data.window_status}` : ''}
                </CardDescription>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('pages.enforcement.columns.control')}</TableHead>
                    <TableHead>{t('pages.enforcement.columns.mode')}</TableHead>
                    <TableHead>{t('pages.enforcement.columns.meaning')}</TableHead>
                    <TableHead className="text-right">{t('pages.enforcement.columns.wouldDeny')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.gates.map((g) => (
                    <GateRow key={g.name} gate={g} />
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {!data.fully_enforcing && (
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle className="text-base">{t('pages.enforcement.envTitle')}</CardTitle>
                  <CardDescription>{t('pages.enforcement.envHint')}</CardDescription>
                </div>
                <Button variant="outline" size="sm" onClick={copyEnv}>
                  <Copy className="mr-1.5 h-3.5 w-3.5" /> {t('pages.enforcement.copy')}
                </Button>
              </CardHeader>
              <CardContent>
                <pre className="rounded-md bg-muted p-3 font-mono text-xs" data-testid="env-lines">
                  {data.env_lines.join('\n')}
                </pre>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
