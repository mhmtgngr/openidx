import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ListChecks, Pencil, Plus, Trash2 } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Label } from './ui/label'
import { Switch } from './ui/switch'
import { Textarea } from './ui/textarea'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from './ui/alert-dialog'
import { QueryGate } from './query-gate'
import { QueryError } from './query-error'
import { api } from '../lib/api'
import { apiErrorBody } from '../lib/api-error'
import { useToast } from '../hooks/use-toast'

/**
 * Device agent checks: the posture checks the OpenIDX agents run on the device.
 *
 * They share the posture_checks table and the /ziti/posture/checks endpoints
 * with the Ziti posture checks on the Ziti Network page, and nothing else. The
 * server tells the two apart by check_type, serves only these to agents, and
 * never mirrors them to the controller. The form is built from the server's own
 * vocabulary (GET /ziti/posture/check-types): the types the agents implement,
 * the platforms each can run on, and the params each reads. So the editor can
 * only offer what the server would accept, and what it accepts is what an agent
 * can run.
 */

export type ParamKind = 'version' | 'integer' | 'boolean' | 'string_list'

export interface AgentParamSpec {
  name: string
  kind: ParamKind
  required?: boolean
  min?: number
  max?: number
}

export interface AgentCheckSpec {
  type: string
  platforms: string[]
  params: AgentParamSpec[]
}

export interface PostureVocabulary {
  ziti: string[]
  agent: AgentCheckSpec[]
  severities: string[]
  platforms: string[]
}

export interface AgentCheckRow {
  id: string
  name: string
  check_type: string
  parameters: Record<string, unknown> | null
  enabled: boolean
  severity: string
  platforms?: string[] | null
  created_at?: string
}

const CHECKS_URL = '/api/v1/access/ziti/posture/checks'
const VOCAB_URL = '/api/v1/access/ziti/posture/check-types'
const CHECKS_KEY = ['agent-posture-checks']

// Platform names are product names, so they stay raw, as on the fleet list.
const PLATFORM_LABELS: Record<string, string> = {
  windows: 'Windows',
  macos: 'macOS',
  linux: 'Linux',
  android: 'Android',
  ios: 'iOS',
}

/** What the form holds per param: text for the typed inputs, a flag for booleans. */
type ParamValues = Record<string, string | boolean>

interface FormState {
  name: string
  check_type: string
  severity: string
  enabled: boolean
  platforms: string[]
  params: ParamValues
}

function emptyParams(spec: AgentCheckSpec | undefined): ParamValues {
  const out: ParamValues = {}
  for (const p of spec?.params ?? []) out[p.name] = p.kind === 'boolean' ? false : ''
  return out
}

function paramsFromRow(spec: AgentCheckSpec | undefined, stored: Record<string, unknown> | null): ParamValues {
  const out = emptyParams(spec)
  for (const p of spec?.params ?? []) {
    const v = stored?.[p.name]
    if (v === undefined || v === null) continue
    if (p.kind === 'boolean') out[p.name] = v === true
    else if (p.kind === 'string_list') out[p.name] = Array.isArray(v) ? v.map(String).join('\n') : String(v)
    else out[p.name] = String(v)
  }
  return out
}

/**
 * The params object to send. An empty optional field is left out, so the agent
 * applies its own default; anything typed is sent as typed and judged by the
 * server, which answers with the field and the reason.
 */
function paramsForRequest(spec: AgentCheckSpec | undefined, values: ParamValues): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const p of spec?.params ?? []) {
    const v = values[p.name]
    if (p.kind === 'boolean') {
      out[p.name] = v === true
      continue
    }
    const text = typeof v === 'string' ? v.trim() : ''
    if (text === '') continue
    if (p.kind === 'string_list') {
      out[p.name] = text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)
    } else if (p.kind === 'integer') {
      const n = Number(text)
      out[p.name] = Number.isInteger(n) ? n : text
    } else {
      out[p.name] = text
    }
  }
  return out
}

function paramSummary(row: AgentCheckRow): string {
  const entries = Object.entries(row.parameters ?? {})
  if (entries.length === 0) return '—'
  return entries
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`)
    .join('; ')
}

export function AgentChecksSection() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const checksQuery = useQuery({
    queryKey: CHECKS_KEY,
    queryFn: () => api.get<AgentCheckRow[]>(`${CHECKS_URL}?kind=agent`),
  })
  const vocabQuery = useQuery({
    queryKey: ['posture-check-types'],
    queryFn: () => api.get<PostureVocabulary>(VOCAB_URL),
  })
  const specs = Array.isArray(vocabQuery.data?.agent) ? vocabQuery.data.agent : []
  const severities = Array.isArray(vocabQuery.data?.severities) ? vocabQuery.data.severities : []
  const specFor = (type: string) => specs.find((s) => s.type === type)

  const [editing, setEditing] = useState<AgentCheckRow | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState<FormState | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<AgentCheckRow | null>(null)

  const typeLabel = (type: string) => t(`pages.agentFleet.checks.types.${type}`, { defaultValue: type })
  const severityLabel = (sev: string) => t(`pages.agentFleet.checks.severities.${sev}`, { defaultValue: sev })

  function openCreate() {
    const first = specs[0]
    setEditing(null)
    setFormError(null)
    setForm({
      name: '',
      check_type: first?.type ?? '',
      severity: 'high',
      enabled: true,
      platforms: [],
      params: emptyParams(first),
    })
    setFormOpen(true)
  }

  function openEdit(row: AgentCheckRow) {
    setEditing(row)
    setFormError(null)
    setForm({
      name: row.name,
      check_type: row.check_type,
      severity: row.severity,
      enabled: row.enabled,
      platforms: Array.isArray(row.platforms) ? row.platforms : [],
      params: paramsFromRow(specFor(row.check_type), row.parameters),
    })
    setFormOpen(true)
  }

  function changeType(type: string) {
    if (!form) return
    const spec = specFor(type)
    setForm({
      ...form,
      check_type: type,
      params: emptyParams(spec),
      // A platform the new type cannot run on would be refused.
      platforms: form.platforms.filter((p) => spec?.platforms.includes(p)),
    })
  }

  const saveMutation = useMutation({
    mutationFn: (f: FormState) => {
      const body = {
        name: f.name.trim(),
        check_type: f.check_type,
        severity: f.severity,
        enabled: f.enabled,
        platforms: f.platforms,
        parameters: paramsForRequest(specFor(f.check_type), f.params),
      }
      return editing ? api.put(`${CHECKS_URL}/${editing.id}`, body) : api.post(CHECKS_URL, body)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CHECKS_KEY })
      toast({ title: editing ? t('pages.agentFleet.checks.toast.updated') : t('pages.agentFleet.checks.toast.created') })
      setFormOpen(false)
      setEditing(null)
    },
    onError: (err) => {
      // The server names what it refused and why; that sentence is the most
      // useful thing to show, and the generic one is the fallback.
      const body = apiErrorBody(err)
      setFormError(typeof body?.error === 'string' ? body.error : t('pages.agentFleet.checks.saveFailed'))
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`${CHECKS_URL}/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: CHECKS_KEY })
      toast({ title: t('pages.agentFleet.checks.toast.deleted') })
      setDeleteTarget(null)
    },
    onError: () => toast({ title: t('common.error'), description: t('pages.agentFleet.checks.toast.deleteFailed'), variant: 'destructive' }),
  })

  const spec = form ? specFor(form.check_type) : undefined

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-3">
        <div className="space-y-1">
          <CardTitle className="flex items-center gap-2">
            <ListChecks className="h-5 w-5 text-muted-foreground" />
            {t('pages.agentFleet.checks.title')}
          </CardTitle>
          <p className="text-sm text-muted-foreground">{t('pages.agentFleet.checks.subtitle')}</p>
        </div>
        <Button size="sm" onClick={openCreate} disabled={specs.length === 0}>
          <Plus className="mr-2 h-4 w-4" /> {t('pages.agentFleet.checks.add')}
        </Button>
      </CardHeader>
      <CardContent>
        {/* Without the vocabulary there is no form to offer; the list below
            does not need it and still shows. */}
        {vocabQuery.isError && (
          <QueryError error={vocabQuery.error} resource={t('pages.agentFleet.checks.vocabResource')} className="py-4" />
        )}
        <QueryGate
          query={checksQuery}
          resource={t('pages.agentFleet.checks.resource')}
          empty={<p className="py-6 text-center text-sm text-muted-foreground">{t('pages.agentFleet.checks.empty')}</p>}
        >
          {(rows) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('pages.agentFleet.checks.colName')}</TableHead>
                  <TableHead>{t('pages.agentFleet.checks.colType')}</TableHead>
                  <TableHead>{t('pages.agentFleet.checks.colSeverity')}</TableHead>
                  <TableHead>{t('pages.agentFleet.checks.colPlatforms')}</TableHead>
                  <TableHead>{t('pages.agentFleet.checks.colParams')}</TableHead>
                  <TableHead>{t('pages.agentFleet.checks.colStatus')}</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(Array.isArray(rows) ? rows : []).map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="font-medium">{row.name}</TableCell>
                    <TableCell><Badge variant="outline">{typeLabel(row.check_type)}</Badge></TableCell>
                    <TableCell>
                      <Badge variant={row.severity === 'critical' || row.severity === 'high' ? 'destructive' : 'secondary'}>
                        {severityLabel(row.severity)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {Array.isArray(row.platforms) && row.platforms.length > 0
                        ? row.platforms.map((p) => PLATFORM_LABELS[p] ?? p).join(', ')
                        : t('pages.agentFleet.checks.allPlatforms')}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{paramSummary(row)}</TableCell>
                    <TableCell>
                      <Badge variant={row.enabled ? 'default' : 'secondary'}>
                        {row.enabled ? t('pages.agentFleet.checks.enabled') : t('pages.agentFleet.checks.disabled')}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" aria-label={t('pages.agentFleet.checks.editLabel', { name: row.name })} onClick={() => openEdit(row)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon" aria-label={t('pages.agentFleet.checks.deleteLabel', { name: row.name })} onClick={() => setDeleteTarget(row)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryGate>
      </CardContent>

      <Dialog open={formOpen} onOpenChange={(open) => { if (!open) { setFormOpen(false); setEditing(null) } }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{editing ? t('pages.agentFleet.checks.editTitle') : t('pages.agentFleet.checks.createTitle')}</DialogTitle>
          </DialogHeader>
          {form && (
            <form
              className="space-y-4"
              onSubmit={(e) => { e.preventDefault(); setFormError(null); saveMutation.mutate(form) }}
            >
              <div className="space-y-2">
                <Label htmlFor="agent-check-name">{t('pages.agentFleet.checks.name')}</Label>
                <Input
                  id="agent-check-name"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder={t('pages.agentFleet.checks.namePlaceholder')}
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="agent-check-type">{t('pages.agentFleet.checks.checkType')}</Label>
                  <select
                    id="agent-check-type"
                    value={form.check_type}
                    onChange={(e) => changeType(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  >
                    {specs.map((s) => (
                      <option key={s.type} value={s.type}>{typeLabel(s.type)}</option>
                    ))}
                  </select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="agent-check-severity">{t('pages.agentFleet.checks.severity')}</Label>
                  <select
                    id="agent-check-severity"
                    value={form.severity}
                    onChange={(e) => setForm({ ...form, severity: e.target.value })}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  >
                    {severities.map((s) => (
                      <option key={s} value={s}>{severityLabel(s)}</option>
                    ))}
                  </select>
                </div>
              </div>
              {spec && (
                <p className="text-xs text-muted-foreground">
                  {t(`pages.agentFleet.checks.typeHints.${spec.type}`, { defaultValue: '' })}
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                {t(`pages.agentFleet.checks.severityHints.${form.severity}`, { defaultValue: '' })}
              </p>

              {(spec?.params ?? []).length > 0 && (
                <fieldset className="space-y-3 rounded-md border p-3">
                  <legend className="px-1 text-sm font-medium">{t('pages.agentFleet.checks.params')}</legend>
                  {(spec?.params ?? []).map((p) => (
                    <ParamField
                      key={p.name}
                      param={p}
                      value={form.params[p.name]}
                      onChange={(v) => setForm({ ...form, params: { ...form.params, [p.name]: v } })}
                    />
                  ))}
                  <p className="text-xs text-muted-foreground">{t('pages.agentFleet.checks.paramsHint')}</p>
                </fieldset>
              )}

              <div className="space-y-2">
                <span className="text-sm font-medium">{t('pages.agentFleet.checks.platforms')}</span>
                <div className="flex flex-wrap gap-3">
                  {(spec?.platforms ?? []).map((p) => (
                    <label key={p} className="flex items-center gap-1.5 text-sm">
                      <input
                        type="checkbox"
                        checked={form.platforms.includes(p)}
                        onChange={(e) =>
                          setForm({
                            ...form,
                            platforms: e.target.checked
                              ? [...form.platforms, p]
                              : form.platforms.filter((x) => x !== p),
                          })
                        }
                      />
                      {PLATFORM_LABELS[p] ?? p}
                    </label>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">{t('pages.agentFleet.checks.platformsHint')}</p>
              </div>

              <div className="flex items-center gap-2">
                <Switch
                  id="agent-check-enabled"
                  checked={form.enabled}
                  onCheckedChange={(checked) => setForm({ ...form, enabled: checked })}
                />
                <Label htmlFor="agent-check-enabled">{t('pages.agentFleet.checks.enabledLabel')}</Label>
              </div>

              {formError && (
                <p role="alert" className="text-sm text-destructive">{formError}</p>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" onClick={() => { setFormOpen(false); setEditing(null) }}>
                  {t('common.cancel')}
                </Button>
                <Button type="submit" disabled={saveMutation.isPending}>
                  {saveMutation.isPending
                    ? t('pages.agentFleet.checks.saving')
                    : editing ? t('pages.agentFleet.checks.editSubmit') : t('pages.agentFleet.checks.createSubmit')}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.agentFleet.checks.deleteTitle')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.agentFleet.checks.deleteDesc', { name: deleteTarget?.name ?? '' })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
            >
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

/** One param's input, shaped by its kind. */
function ParamField({ param, value, onChange }: {
  param: AgentParamSpec
  value: string | boolean | undefined
  onChange: (v: string | boolean) => void
}) {
  const { t } = useTranslation()
  const id = `agent-check-param-${param.name}`
  const label = t(`pages.agentFleet.checks.paramLabels.${param.name}`, { defaultValue: param.name })
  const hint = t(`pages.agentFleet.checks.paramHints.${param.name}`, { defaultValue: '' })

  if (param.kind === 'boolean') {
    return (
      <div className="flex items-center gap-2">
        <Switch id={id} checked={value === true} onCheckedChange={(checked) => onChange(checked)} />
        <Label htmlFor={id}>{label}</Label>
      </div>
    )
  }
  const text = typeof value === 'string' ? value : ''
  return (
    <div className="space-y-1">
      <Label htmlFor={id}>
        {label}
        {param.required && <span className="text-destructive"> *</span>}
      </Label>
      {param.kind === 'string_list' ? (
        <Textarea id={id} value={text} rows={3} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <Input
          id={id}
          value={text}
          inputMode={param.kind === 'integer' ? 'numeric' : undefined}
          placeholder={param.kind === 'version' ? '10.0.19045' : param.kind === 'integer' ? `${param.min ?? ''}–${param.max ?? ''}` : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}
