import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { FileText, Download, Clock, Trash2, Pencil } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { api } from '../lib/api'
import { QueryError } from '../components/query-error'
import { ConfirmAction } from '../components/confirm-action'
import { useToast } from '../hooks/use-toast'

const REPORT_TYPES = ['user_access', 'compliance', 'entitlement', 'activity'] as const

interface ReportExport {
  id: string
  name: string
  report_type: string
  framework: string
  format: string
  status: string
  file_size: number
  row_count: number
  error_message: string
  generated_by: string
  created_at: string
  completed_at?: string
}

interface ScheduledReport {
  id: string
  name: string
  description: string
  report_type: string
  framework: string
  schedule: string
  format: string
  enabled: boolean
  last_run_at?: string
  next_run_at?: string
  created_at: string
}

export function ReportsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [tab, setTab] = useState<'exports' | 'scheduled'>('exports')
  const [generateOpen, setGenerateOpen] = useState(false)
  const [scheduleOpen, setScheduleOpen] = useState(false)
  const [editSchedule, setEditSchedule] = useState<ScheduledReport | null>(null)

  const [genForm, setGenForm] = useState({ report_type: 'user_access', framework: '', format: 'csv' })
  const [schedForm, setSchedForm] = useState({ name: '', report_type: 'user_access', framework: '', schedule: '0 0 * * 1', format: 'csv', enabled: true })

  const { data: exportsData, isLoading: exportsLoading, isError: exportsError, error: exportsErrorObj } = useQuery({
    queryKey: ['report-exports'],
    queryFn: async () => {
      const res = await api.get<{ exports: ReportExport[]; total: number }>('/api/v1/audit/reports/exports')
      // Normalize so rendered fields never throw when the backend omits them
      // (Go zero-values / nil slices serialize to null or are dropped).
      const exports = (res?.exports ?? []).map(exp => ({
        ...exp,
        name: exp.name ?? '',
        report_type: exp.report_type ?? '',
        format: exp.format ?? '',
        status: exp.status ?? '',
        file_size: exp.file_size ?? 0,
        row_count: exp.row_count ?? 0,
        created_at: exp.created_at ?? '',
      }))
      return { exports, total: res?.total ?? 0 }
    },
    refetchInterval: 5000,
  })
  const exports = exportsData?.exports || []

  const { data: scheduledData, isLoading: scheduledLoading, isError: scheduledError, error: scheduledErrorObj } = useQuery({
    queryKey: ['scheduled-reports'],
    queryFn: async () => {
      const res = await api.get<{ reports: ScheduledReport[] }>('/api/v1/audit/reports/scheduled')
      const reports = (res?.reports ?? []).map(s => ({
        ...s,
        name: s.name ?? '',
        report_type: s.report_type ?? '',
        schedule: s.schedule ?? '',
        format: s.format ?? '',
      }))
      return { reports }
    },
  })
  const scheduled = scheduledData?.reports || []

  const generateMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/audit/reports/generate', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report-exports'] })
      toast({ title: t('pages.reports.toast.generationStarted') })
      setGenerateOpen(false)
    },
    onError: () => toast({ title: t('pages.reports.toast.generateFailed'), variant: 'destructive' }),
  })

  // Download an export through the authenticated api client (blob), not a bare
  // window.open — the download endpoint requires the Authorization header, so a
  // plain URL opened in a new tab returned {"error":"missing authorization
  // header"} instead of the file. Fetch the bytes with the bearer token, then
  // save via a temporary object-URL anchor.
  const downloadMutation = useMutation({
    mutationFn: async (exp: ReportExport) => {
      const blob = await api.get<Blob>(
        `/api/v1/audit/reports/exports/${exp.id}/download`,
        { responseType: 'blob' },
      )
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ext = (exp.format || 'csv').toLowerCase()
      const safeName = (exp.name || 'report').replace(/[^\w.-]+/g, '_')
      a.download = safeName.endsWith(`.${ext}`) ? safeName : `${safeName}.${ext}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      // Revoke on the next tick so the click has consumed the URL.
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
    onError: () => toast({ title: t('pages.reports.toast.downloadFailed'), variant: 'destructive' }),
  })

  const createScheduleMutation = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.post('/api/v1/audit/reports/scheduled', body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-reports'] })
      toast({ title: t(editSchedule ? 'pages.reports.toast.scheduleUpdated' : 'pages.reports.toast.scheduleCreated') })
      setScheduleOpen(false)
    },
    onError: () => toast({ title: t('pages.reports.toast.saveFailed'), variant: 'destructive' }),
  })

  const updateScheduleMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api.put(`/api/v1/audit/reports/scheduled/${id}`, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-reports'] })
      toast({ title: t('pages.reports.toast.scheduleUpdated') })
      setScheduleOpen(false)
    },
  })

  const deleteScheduleMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/audit/reports/scheduled/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-reports'] })
      toast({ title: t('pages.reports.toast.scheduleDeleted') })
    },
  })

  const openGenerate = () => {
    setGenForm({ report_type: 'user_access', framework: '', format: 'csv' })
    setGenerateOpen(true)
  }

  const openSchedule = (s?: ScheduledReport) => {
    setEditSchedule(s || null)
    setSchedForm(s ? { name: s.name, report_type: s.report_type, framework: s.framework, schedule: s.schedule, format: s.format, enabled: s.enabled } :
      { name: '', report_type: 'user_access', framework: '', schedule: '0 0 * * 1', format: 'csv', enabled: true })
    setScheduleOpen(true)
  }

  const handleSaveSchedule = () => {
    if (editSchedule) {
      updateScheduleMutation.mutate({ id: editSchedule.id, body: schedForm })
    } else {
      createScheduleMutation.mutate(schedForm)
    }
  }

  const formatSize = (bytes: number) => {
    if (!bytes) return '-'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const statusColor = (s: string) => {
    switch (s) {
      case 'completed': return 'default'
      case 'generating': return 'secondary'
      case 'failed': return 'destructive'
      default: return 'outline'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.reports.title')}</h1>
          <p className="text-muted-foreground">{t('pages.reports.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => openSchedule()}><Clock className="mr-2 h-4 w-4" />{t('pages.reports.scheduleReport')}</Button>
          <Button onClick={openGenerate}><FileText className="mr-2 h-4 w-4" />{t('pages.reports.generateReport')}</Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b pb-2">
        <Button variant={tab === 'exports' ? 'default' : 'ghost'} size="sm" onClick={() => setTab('exports')}>{t('pages.reports.tabExports')}</Button>
        <Button variant={tab === 'scheduled' ? 'default' : 'ghost'} size="sm" onClick={() => setTab('scheduled')}>{t('pages.reports.tabScheduled')}</Button>
      </div>

      {tab === 'exports' && (
        <Card>
          <CardHeader><CardTitle>{t('pages.reports.generatedReports')}</CardTitle></CardHeader>
          <CardContent>
            {exportsLoading ? <p className="text-center py-8 text-muted-foreground">{t('common.loading')}</p> :
             exportsError ? <QueryError error={exportsErrorObj} resource={t('pages.reports.exportsResource')} /> :
             exports.length === 0 ? <p className="text-center py-8 text-muted-foreground">{t('pages.reports.noExports')}</p> : (
              <Table>
                <TableHeader><TableRow>
                  <TableHead>{t('pages.reports.columns.name')}</TableHead><TableHead>{t('pages.reports.columns.type')}</TableHead><TableHead>{t('pages.reports.columns.format')}</TableHead>
                  <TableHead>{t('pages.reports.columns.status')}</TableHead><TableHead>{t('pages.reports.columns.size')}</TableHead><TableHead>{t('pages.reports.columns.rows')}</TableHead>
                  <TableHead>{t('pages.reports.columns.created')}</TableHead><TableHead>{t('pages.reports.columns.actions')}</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {exports.map(exp => (
                    <TableRow key={exp.id}>
                      <TableCell className="font-medium">{exp.name}</TableCell>
                      <TableCell><Badge variant="outline">{exp.report_type}</Badge></TableCell>
                      <TableCell>{exp.format.toUpperCase()}</TableCell>
                      <TableCell><Badge variant={statusColor(exp.status) as 'default' | 'secondary' | 'destructive' | 'outline'}>{exp.status}</Badge></TableCell>
                      <TableCell>{formatSize(exp.file_size)}</TableCell>
                      <TableCell>{exp.row_count || '-'}</TableCell>
                      <TableCell>{new Date(exp.created_at).toLocaleString()}</TableCell>
                      <TableCell>
                        {exp.status === 'completed' && (
                          <Button size="sm" variant="ghost" disabled={downloadMutation.isPending} onClick={() => downloadMutation.mutate(exp)}>
                            <Download className="h-4 w-4" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}

      {tab === 'scheduled' && (
        <Card>
          <CardHeader><CardTitle>{t('pages.reports.tabScheduled')}</CardTitle></CardHeader>
          <CardContent>
            {scheduledLoading ? <p className="text-center py-8 text-muted-foreground">{t('common.loading')}</p> :
             scheduledError ? <QueryError error={scheduledErrorObj} resource={t('pages.reports.scheduledResource')} /> :
             scheduled.length === 0 ? <p className="text-center py-8 text-muted-foreground">{t('pages.reports.noScheduled')}</p> : (
              <Table>
                <TableHeader><TableRow>
                  <TableHead>{t('pages.reports.columns.name')}</TableHead><TableHead>{t('pages.reports.columns.type')}</TableHead><TableHead>{t('pages.reports.columns.schedule')}</TableHead>
                  <TableHead>{t('pages.reports.columns.format')}</TableHead><TableHead>{t('pages.reports.columns.status')}</TableHead><TableHead>{t('pages.reports.columns.lastRun')}</TableHead><TableHead>{t('pages.reports.columns.actions')}</TableHead>
                </TableRow></TableHeader>
                <TableBody>
                  {scheduled.map(s => (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium">{s.name}</TableCell>
                      <TableCell><Badge variant="outline">{s.report_type}</Badge></TableCell>
                      <TableCell className="font-mono text-sm">{s.schedule}</TableCell>
                      <TableCell>{s.format.toUpperCase()}</TableCell>
                      <TableCell><Badge variant={s.enabled ? 'default' : 'secondary'}>{t(s.enabled ? 'pages.reports.active' : 'pages.reports.disabled')}</Badge></TableCell>
                      <TableCell>{s.last_run_at ? new Date(s.last_run_at).toLocaleString() : t('pages.reports.never')}</TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button variant="ghost" size="sm" onClick={() => openSchedule(s)}><Pencil className="h-4 w-4" /></Button>
                          <ConfirmAction
                            title={t('pages.reports.deleteTitle')}
                            description={t('pages.reports.deleteDesc', { name: s.name })}
                            destructive
                            confirmLabel={t('common.delete')}
                            onConfirm={() => deleteScheduleMutation.mutateAsync(s.id)}
                          >
                            {(open) => (
                              <Button variant="ghost" size="sm" onClick={open}><Trash2 className="h-4 w-4 text-red-500" /></Button>
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

      {/* Generate Report Dialog */}
      <Dialog open={generateOpen} onOpenChange={setGenerateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('pages.reports.dialog.generateTitle')}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label htmlFor="reports-report-type" className="text-sm font-medium">{t('pages.reports.dialog.reportType')}</label>
              <Select value={genForm.report_type} onValueChange={v => setGenForm(f => ({ ...f, report_type: v }))}>
                <SelectTrigger id="reports-report-type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {REPORT_TYPES.map(rt => (
                    <SelectItem key={rt} value={rt}>{t(`pages.reports.reportTypes.${rt}`)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {genForm.report_type === 'compliance' && (
              <div>
                <label htmlFor="reports-framework" className="text-sm font-medium">{t('pages.reports.dialog.framework')}</label>
                <Select value={genForm.framework} onValueChange={v => setGenForm(f => ({ ...f, framework: v }))}>
                  <SelectTrigger id="reports-framework"><SelectValue placeholder={t('pages.reports.dialog.selectFramework')} /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="SOC2">SOC 2</SelectItem>
                    <SelectItem value="ISO27001">ISO 27001</SelectItem>
                    <SelectItem value="HIPAA">HIPAA</SelectItem>
                    <SelectItem value="PCI-DSS">PCI-DSS</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div>
              <label htmlFor="reports-format" className="text-sm font-medium">{t('pages.reports.dialog.format')}</label>
              <Select value={genForm.format} onValueChange={v => setGenForm(f => ({ ...f, format: v }))}>
                <SelectTrigger id="reports-format"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGenerateOpen(false)}>{t('common.cancel')}</Button>
            <Button onClick={() => generateMutation.mutate(genForm)} disabled={generateMutation.isPending}>{t('pages.reports.dialog.generate')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Schedule Report Dialog */}
      <Dialog open={scheduleOpen} onOpenChange={setScheduleOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t(editSchedule ? 'pages.reports.dialog.editTitle' : 'pages.reports.dialog.createTitle')}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">{t('pages.reports.dialog.name')}</label>
              <Input value={schedForm.name} onChange={e => setSchedForm(f => ({ ...f, name: e.target.value }))} placeholder={t('pages.reports.dialog.namePlaceholder')} />
            </div>
            <div>
              <label htmlFor="reports-report-type-2" className="text-sm font-medium">{t('pages.reports.dialog.reportType')}</label>
              <Select value={schedForm.report_type} onValueChange={v => setSchedForm(f => ({ ...f, report_type: v }))}>
                <SelectTrigger id="reports-report-type-2"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {REPORT_TYPES.map(rt => (
                    <SelectItem key={rt} value={rt}>{t(`pages.reports.reportTypes.${rt}`)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-sm font-medium">{t('pages.reports.dialog.cronSchedule')}</label>
              <Input value={schedForm.schedule} onChange={e => setSchedForm(f => ({ ...f, schedule: e.target.value }))} placeholder="0 0 * * 1" />
              <p className="text-xs text-muted-foreground mt-1">{t('pages.reports.dialog.cronHint')}</p>
            </div>
            <div>
              <label htmlFor="reports-format-2" className="text-sm font-medium">{t('pages.reports.dialog.format')}</label>
              <Select value={schedForm.format} onValueChange={v => setSchedForm(f => ({ ...f, format: v }))}>
                <SelectTrigger id="reports-format-2"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={schedForm.enabled} onChange={e => setSchedForm(f => ({ ...f, enabled: e.target.checked }))} />
              {t('pages.reports.dialog.enabled')}
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setScheduleOpen(false)}>{t('common.cancel')}</Button>
            <Button disabled={!schedForm.name} onClick={handleSaveSchedule}>
              {t(editSchedule ? 'pages.reports.dialog.update' : 'pages.reports.dialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
