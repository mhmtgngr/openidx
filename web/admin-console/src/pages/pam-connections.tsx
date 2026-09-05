import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Folder, FolderPlus, Plus, Search, Star, Play, Eye, Trash2, Pencil, Upload,
  Server, Terminal, Monitor, Globe, KeyRound, StickyNote, CreditCard, ShieldCheck, Shield,
  Send, Copy, Lock, Route, AlertTriangle, AppWindow,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
import { Checkbox } from '../components/ui/checkbox'
import { LoadingSpinner } from '../components/ui/loading-spinner'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '../components/ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '../components/ui/select'
import {
  api, PamEntry, PamEntryType, PamFolder, PamEntryInput, PamConnectResult, PamImportResult,
} from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'
import { useRevealedSecret, copyWithWarning } from '../lib/secret-reveal'
import { TerminalSession } from '../components/remote/terminal-session'
import { connectionPathSteps } from '../lib/connection-path'
import { remoteAppArgsLookSecret, remoteAppSecretHint } from '../lib/remote-app'

// Random, unguessable key for the single-use /pam-session localStorage handoff.
// Prefer crypto.randomUUID, but fall back to getRandomValues hex so this still
// works in insecure contexts (the console may be served over plain HTTP).
function randomHandoffKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

// Icon + accent per entry type, so the list reads like RDM's typed tree.
const typeIcon = (t: string) => {
  switch (t) {
    case 'rdp': return Monitor
    case 'windows_app_host': return AppWindow
    case 'ssh':
    case 'telnet': return Terminal
    case 'vnc': return Server
    case 'website':
    case 'website_login': return Globe
    case 'credential':
    case 'ssh_key':
    case 'api_key':
    case 'certificate': return KeyRound
    case 'credit_card':
    case 'bank_account': return CreditCard
    default: return StickyNote
  }
}

const kindBadge: Record<string, string> = {
  session: 'bg-blue-100 text-blue-800',
  credential: 'bg-purple-100 text-purple-800',
  info: 'bg-muted text-foreground',
}

// Common RemoteApp publications; picking one pre-fills the alias/args so
// admins don't have to know Guacamole's parameter names. Aliases must match
// what the RDS host publishes (New-RDRemoteApp -Alias ...).
// Product names — deliberately untranslated.
const remoteAppPresets: { label: string; alias: string; args?: string }[] = [
  { label: 'SQL Server Management Studio', alias: 'SSMS', args: '-E' },
  { label: 'PowerShell', alias: 'PowerShell' },
  { label: 'Visual Studio Code', alias: 'Code' },
  { label: 'Google Chrome', alias: 'Chrome' },
]

const emptyForm: PamEntryInput = {
  name: '', entry_type: 'rdp', description: '', tags: [],
  hostname: '', port: 0, username: '', domain: '', url: '',
  settings: {}, secret: '', credential_entry_id: '',
  allow_reveal: false, require_approval: false, record_session: false,
}

export function PamConnectionsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [selectedFolder, setSelectedFolder] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [favoritesOnly, setFavoritesOnly] = useState(false)

  const [showEntryDialog, setShowEntryDialog] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<PamEntryInput>(emptyForm)

  const [showFolderDialog, setShowFolderDialog] = useState(false)
  const [folderName, setFolderName] = useState('')

  const [showImport, setShowImport] = useState(false)
  const [importData, setImportData] = useState('')
  const [importResult, setImportResult] = useState<PamImportResult | null>(null)

  // Clientless in-browser SSH terminal (wasm-ssh renderer). When set, a dialog
  // hosts the xterm session for this entry instead of opening a guac tab.
  const [terminalEntry, setTerminalEntry] = useState<PamEntry | null>(null)

  const [revealFor, setRevealFor] = useState<PamEntry | null>(null)
  const [revealReason, setRevealReason] = useState('')
  // Revealed plaintext auto-clears after the TTL and on unmount (never lingers in state).
  const { value: revealedValue, reveal: revealSecret, clear: clearRevealed } = useRevealedSecret()

  const [requestFor, setRequestFor] = useState<PamEntry | null>(null)
  const [requestReason, setRequestReason] = useState('')

  const [deleteEntry, setDeleteEntry] = useState<PamEntry | null>(null)

  // "How does this connect" explainer dialog for a session entry.
  const [pathEntry, setPathEntry] = useState<PamEntry | null>(null)

  const { data: typesData } = useQuery({
    queryKey: ['pam-entry-types'],
    queryFn: () => api.pam.listEntryTypes(),
  })
  const entryTypes: PamEntryType[] = typesData?.types || []

  const { data: foldersData } = useQuery({
    queryKey: ['pam-folders'],
    queryFn: () => api.pam.listFolders(),
  })
  const folders: PamFolder[] = foldersData?.folders || []

  const { data: entriesData, isLoading, isError, error } = useQuery({
    queryKey: ['pam-entries', selectedFolder, search, favoritesOnly],
    queryFn: () => api.pam.listEntries({
      folder_id: selectedFolder || undefined,
      q: search || undefined,
      favorites: favoritesOnly || undefined,
    }),
  })
  const entries: PamEntry[] = useMemo(() => entriesData?.entries || [], [entriesData])

  const credentialEntries = useMemo(
    () => entries.filter((e) => e.kind === 'credential'),
    [entries],
  )

  // How many loaded session entries borrow each credential entry's secret —
  // makes the credential ↔ session relationship visible from both sides.
  const credentialUsage = useMemo(() => {
    const usage = new Map<string, string[]>()
    for (const e of entries) {
      if (e.credential_entry_id) {
        usage.set(e.credential_entry_id, [...(usage.get(e.credential_entry_id) || []), e.name])
      }
    }
    return usage
  }, [entries])

  const selectedType = entryTypes.find((t) => t.type === form.entry_type)

  // RemoteApp (single published Windows app instead of a full desktop). These
  // are plain Guacamole RDP parameters carried in the entry's settings JSON —
  // the backend already forwards non-reserved settings to guacd, so SSMS &co
  // launch passwordless through the existing vault-injected flow.
  const settingStr = (key: string): string => {
    const v = form.settings?.[key]
    return typeof v === 'string' ? v : ''
  }
  const setSetting = (key: string, value: string) =>
    setForm((f) => {
      const next: Record<string, unknown> = { ...(f.settings || {}) }
      if (value) next[key] = value
      else delete next[key]
      return { ...f, settings: next }
    })
  // Guacamole expects RemoteApp aliases in the "||alias" form the RDS host
  // registers them under; prefix automatically so admins can type "SSMS".
  const setRemoteAppAlias = (raw: string) => {
    const trimmed = raw.trim()
    setSetting('remote-app', trimmed && !trimmed.startsWith('||') ? `||${trimmed}` : trimmed)
  }

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['pam-entries'] })
    queryClient.invalidateQueries({ queryKey: ['pam-folders'] })
  }

  const saveEntry = useMutation({
    mutationFn: () => {
      const body: PamEntryInput = {
        ...form,
        folder_id: form.folder_id || selectedFolder || undefined,
        port: form.port ? Number(form.port) : undefined,
        secret: form.secret || undefined,
        credential_entry_id: form.credential_entry_id || undefined,
      }
      return editingId ? api.pam.updateEntry(editingId, body) : api.pam.createEntry(body)
    },
    onSuccess: () => {
      invalidate()
      setShowEntryDialog(false)
      setForm(emptyForm)
      setEditingId(null)
      toast({
        title: editingId
          ? t('pages.pamConnections.toasts.entryUpdated')
          : t('pages.pamConnections.toasts.entryCreated'),
      })
    },
    onError: (e: Error) =>
      toast({
        title: t('pages.pamConnections.toasts.saveFailed'),
        description: e.message,
        variant: 'destructive',
      }),
  })

  const createFolder = useMutation({
    mutationFn: () => api.pam.createFolder({ name: folderName, parent_id: selectedFolder || undefined }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pam-folders'] })
      setShowFolderDialog(false)
      setFolderName('')
      toast({ title: t('pages.pamConnections.toasts.folderCreated') })
    },
  })

  const toggleFavorite = useMutation({
    mutationFn: (entry: PamEntry) =>
      entry.favorite ? api.pam.unfavorite(entry.id) : api.pam.favorite(entry.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['pam-entries'] }),
  })

  const connect = useMutation({
    mutationFn: (vars: { id: string; name: string }) => api.pam.connect(vars.id),
    onSuccess: (res: PamConnectResult, vars) => {
      const url = res.connect_url || res.url
      if (url) {
        // Open each session in its OWN window pointed at our chrome-less
        // /pam-session wrapper (NOT the raw guac URL). The wrapper frames the
        // guac client and, on failure/disconnect, shows OpenIDX messaging —
        // never Guacamole's own home/connection-manager. Users can launch
        // several connections, each in a separate window.
        //
        // The connect URL carries a token, so we must NOT put it in the URL or
        // browser history: hand it off via a single-use localStorage entry the
        // wrapper reads and immediately deletes.
        const key = randomHandoffKey()
        try {
          localStorage.setItem(
            'pam-session:' + key,
            JSON.stringify({ url, title: vars.name }),
          )
        } catch { /* private-mode / quota — window will show the expired card */ }
        window.open('/pam-session?k=' + key, '_blank')
        toast({
          title: t('pages.pamConnections.toasts.launched'),
          description: res.credential_injected
            ? t('pages.pamConnections.toasts.launchedInjected')
            : undefined,
        })
      } else {
        toast({ title: t('pages.pamConnections.toasts.nothingToLaunch'), variant: 'destructive' })
      }
    },
    onError: (e: Error & { status?: number; body?: PamConnectResult }) => {
      if (e.body?.approval_required || /requires approval/i.test(e.message)) {
        toast({
          title: t('pages.pamConnections.toasts.approvalRequired'),
          description: t('pages.pamConnections.toasts.approvalRequiredDesc'),
          variant: 'destructive',
        })
      } else {
        toast({
          title: t('pages.pamConnections.toasts.launchFailed'),
          description: e.message,
          variant: 'destructive',
        })
      }
    },
  })

  // launch dispatches on the entry's renderer: wasm-ssh opens the in-browser
  // terminal dialog (no guac tab); everything else uses the existing connect
  // flow (guacamole tab / website URL). The permission + approval gate is
  // enforced server-side for both paths.
  const launch = (entry: PamEntry) => {
    if (entry.renderer === 'wasm-ssh') {
      setTerminalEntry(entry)
      return
    }
    connect.mutate({ id: entry.id, name: entry.name })
  }

  const del = useMutation({
    mutationFn: (id: string) => api.pam.deleteEntry(id),
    onSuccess: () => {
      invalidate()
      setDeleteEntry(null)
      toast({ title: t('pages.pamConnections.toasts.entryDeleted') })
    },
  })

  const { data: broker } = useQuery({
    queryKey: ['pam-broker-status'],
    queryFn: () => api.pam.brokerStatus(),
  })
  const zitiAvailable = broker?.reach_modes?.includes('ziti') ?? false

  const toggleZiti = useMutation({
    mutationFn: (entry: PamEntry) =>
      entry.ziti_enabled ? api.pam.disableZiti(entry.id) : api.pam.enableZiti(entry.id),
    onSuccess: (res: { reach_mode: string }) => {
      invalidate()
      toast({
        title: res.reach_mode === 'ziti'
          ? t('pages.pamConnections.toasts.zitiEnabled')
          : t('pages.pamConnections.toasts.zitiDisabled'),
        description: res.reach_mode === 'ziti'
          ? t('pages.pamConnections.toasts.zitiEnabledDesc')
          : t('pages.pamConnections.toasts.zitiDisabledDesc'),
      })
    },
    onError: (e: Error) =>
      toast({
        title: t('pages.pamConnections.toasts.zitiFailed'),
        description: e.message,
        variant: 'destructive',
      }),
  })

  const reveal = useMutation({
    mutationFn: () => api.pam.reveal(revealFor!.id, revealReason),
    onSuccess: (res: { value: string }) => revealSecret(res.value),
    onError: (e: Error) =>
      toast({
        title: t('pages.pamConnections.toasts.revealFailed'),
        description: e.message,
        variant: 'destructive',
      }),
  })

  const requestAccess = useMutation({
    mutationFn: () => api.pam.requestAccess(requestFor!.id, requestReason),
    onSuccess: () => {
      setRequestFor(null)
      setRequestReason('')
      toast({
        title: t('pages.pamConnections.toasts.accessRequested'),
        description: t('pages.pamConnections.toasts.accessRequestedDesc'),
      })
    },
  })

  const runImport = useMutation({
    mutationFn: () => api.pam.importRDM(importData, selectedFolder || undefined),
    onSuccess: (res: PamImportResult) => {
      setImportResult(res)
      setImportData('')
      invalidate()
      toast({
        title: t('pages.pamConnections.toasts.importComplete'),
        description: t('pages.pamConnections.toasts.importCompleteDesc', {
          entries: res.entries_created,
          folders: res.folders_created,
        }),
      })
    },
    onError: (e: Error) =>
      toast({
        title: t('pages.pamConnections.toasts.importFailed'),
        description: e.message,
        variant: 'destructive',
      }),
  })

  const openCreate = () => {
    setEditingId(null)
    setForm({ ...emptyForm, folder_id: selectedFolder || undefined })
    setShowEntryDialog(true)
  }

  const openEdit = (entry: PamEntry) => {
    setEditingId(entry.id)
    setForm({
      folder_id: entry.folder_id, name: entry.name, entry_type: entry.entry_type,
      description: entry.description, tags: entry.tags, hostname: entry.hostname,
      port: entry.port, username: entry.username, domain: entry.domain, url: entry.url,
      settings: entry.settings || {},
      secret: '', credential_entry_id: entry.credential_entry_id,
      allow_reveal: entry.allow_reveal, require_approval: entry.require_approval,
      record_session: entry.record_session, renderer: entry.renderer,
    })
    setShowEntryDialog(true)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Server className="h-6 w-6" /> {t('nav.items.connections')}
          </h1>
          <p className="text-muted-foreground">{t('pages.pamConnections.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => { setImportResult(null); setShowImport(true) }}>
            <Upload className="h-4 w-4 mr-1" /> {t('pages.pamConnections.importRdm')}
          </Button>
          <Button variant="outline" onClick={() => setShowFolderDialog(true)}>
            <FolderPlus className="h-4 w-4 mr-1" /> {t('pages.pamConnections.newFolder')}
          </Button>
          <Button onClick={openCreate}>
            <Plus className="h-4 w-4 mr-1" /> {t('pages.pamConnections.newEntry')}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Folder tree */}
        <Card className="lg:col-span-1 h-fit">
          <CardHeader><CardTitle className="text-sm">{t('pages.pamConnections.folders')}</CardTitle></CardHeader>
          <CardContent className="space-y-1">
            <button
              className={`w-full text-left px-2 py-1.5 rounded text-sm flex items-center gap-2 ${selectedFolder === null ? 'bg-primary/10 font-medium' : 'hover:bg-muted'}`}
              onClick={() => setSelectedFolder(null)}
            >
              <Folder className="h-4 w-4" /> {t('pages.pamConnections.allConnections')}
            </button>
            {folders.map((f) => (
              <button
                key={f.id}
                className={`w-full text-left px-2 py-1.5 rounded text-sm flex items-center justify-between gap-2 ${selectedFolder === f.id ? 'bg-primary/10 font-medium' : 'hover:bg-muted'}`}
                style={{ paddingLeft: f.parent_id ? '1.75rem' : '0.5rem' }}
                onClick={() => setSelectedFolder(f.id)}
              >
                <span className="flex items-center gap-2 truncate"><Folder className="h-4 w-4 shrink-0" /> {f.name}</span>
                <Badge variant="outline" className="shrink-0">{f.entry_count}</Badge>
              </button>
            ))}
          </CardContent>
        </Card>

        {/* Entry list */}
        <div className="lg:col-span-3 space-y-4">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder={t('pages.pamConnections.searchPlaceholder')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Button
              variant={favoritesOnly ? 'default' : 'outline'}
              onClick={() => setFavoritesOnly((v) => !v)}
            >
              <Star className="h-4 w-4 mr-1" /> {t('pages.pamConnections.favorites')}
            </Button>
          </div>

          {isLoading ? (
            <div className="flex justify-center py-12"><LoadingSpinner /></div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.pamConnections.resourceName')} />
          ) : entries.length === 0 ? (
            <Card><CardContent className="py-12 text-center text-muted-foreground">
              {t('pages.pamConnections.empty')}
            </CardContent></Card>
          ) : (
            <div className="space-y-2">
              {entries.map((entry) => {
                const Icon = typeIcon(entry.entry_type)
                const launchable = entry.kind === 'session'
                return (
                  <Card key={entry.id} className="hover:border-primary/40 transition-colors">
                    <CardContent className="flex items-center gap-3 py-3">
                      <button onClick={() => toggleFavorite.mutate(entry)} title={t('pages.pamConnections.badges.favorite')}>
                        <Star className={`h-4 w-4 ${entry.favorite ? 'fill-yellow-400 text-yellow-500' : 'text-muted-foreground'}`} />
                      </button>
                      <Icon className="h-5 w-5 text-muted-foreground shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium truncate">{entry.name}</span>
                          <Badge className={kindBadge[entry.kind] || ''}>{entry.entry_type}</Badge>
                          {entry.require_approval && <Badge variant="outline" title={t('pages.pamConnections.badges.requiresApproval')}><Lock className="h-3 w-3" /></Badge>}
                          {entry.record_session && <Badge variant="outline">{t('pages.pamConnections.badges.recording')}</Badge>}
                          {typeof entry.settings['remote-app'] === 'string' && entry.settings['remote-app'] !== '' && (
                            <Badge
                              variant="outline"
                              title={t('pages.pamConnections.badges.remoteAppTitle')}
                            >
                              {t('pages.pamConnections.badges.remoteApp', {
                                alias: String(entry.settings['remote-app']).replace(/^\|\|/, ''),
                              })}
                            </Badge>
                          )}
                          {entry.has_secret && <Badge variant="outline" title={t('pages.pamConnections.badges.vaultedSecret')}><KeyRound className="h-3 w-3" /></Badge>}
                          {entry.ziti_enabled && <Badge className="bg-emerald-100 text-emerald-800" title={t('pages.pamConnections.badges.zitiTitle')}><Shield className="h-3 w-3 mr-1" />{t('pages.pamConnections.badges.ziti')}</Badge>}
                          {entry.kind === 'credential' && (credentialUsage.get(entry.id)?.length ?? 0) > 0 && (
                            <Badge
                              variant="outline"
                              title={t('pages.pamConnections.badges.usedByTitle', {
                                names: credentialUsage.get(entry.id)!.join(', '),
                              })}
                            >
                              {t('pages.pamConnections.badges.usedBy', {
                                count: credentialUsage.get(entry.id)!.length,
                              })}
                            </Badge>
                          )}
                        </div>
                        <div className="text-xs text-muted-foreground truncate">
                          {entry.hostname && <span>{entry.username ? `${entry.username}@` : ''}{entry.hostname}{entry.port ? `:${entry.port}` : ''}</span>}
                          {entry.url && <span>{entry.url}</span>}
                          {entry.credential_entry_name && (
                            <span>
                              {' · '}
                              {t('pages.pamConnections.badges.linkedCredential', {
                                name: entry.credential_entry_name,
                              })}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        {launchable && (
                          <Button size="sm" onClick={() => launch(entry)} disabled={connect.isPending}>
                            <Play className="h-4 w-4 mr-1" /> {t('pages.pamConnections.actions.connect')}
                          </Button>
                        )}
                        {entry.require_approval && (
                          <Button size="sm" variant="outline" onClick={() => { setRequestFor(entry); setRequestReason('') }} title={t('pages.pamConnections.actions.requestAccess')}>
                            <Send className="h-4 w-4" />
                          </Button>
                        )}
                        {entry.has_secret && entry.allow_reveal && (
                          <Button size="sm" variant="outline" onClick={() => { setRevealFor(entry); setRevealReason(''); clearRevealed() }} title={t('pages.pamConnections.actions.revealSecret')}>
                            <Eye className="h-4 w-4" />
                          </Button>
                        )}
                        {launchable && (zitiAvailable || entry.ziti_enabled) && (
                          <Button
                            size="sm"
                            variant={entry.ziti_enabled ? 'default' : 'outline'}
                            onClick={() => toggleZiti.mutate(entry)}
                            disabled={toggleZiti.isPending}
                            title={entry.ziti_enabled
                              ? t('pages.pamConnections.actions.zitiDisable')
                              : t('pages.pamConnections.actions.zitiEnable')}
                          >
                            <Shield className="h-4 w-4" />
                          </Button>
                        )}
                        {launchable && (
                          <Button size="sm" variant="ghost" onClick={() => setPathEntry(entry)} title={t('pages.pamConnections.actions.launchPath')}>
                            <Route className="h-4 w-4" />
                          </Button>
                        )}
                        <Button size="sm" variant="ghost" onClick={() => openEdit(entry)} title={t('pages.pamConnections.actions.edit')}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => setDeleteEntry(entry)} title={t('pages.pamConnections.actions.delete')}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {/* Entry create/edit dialog */}
      <Dialog open={showEntryDialog} onOpenChange={setShowEntryDialog}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editingId
                ? t('pages.pamConnections.entryDialog.editTitle')
                : t('pages.pamConnections.entryDialog.createTitle')}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="pam-connections-type" className="text-sm font-medium">{t('pages.pamConnections.entryDialog.type')}</label>
                <Select value={form.entry_type} onValueChange={(v) => setForm((f) => ({ ...f, entry_type: v }))} disabled={!!editingId}>
                  <SelectTrigger id="pam-connections-type"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {entryTypes.map((t) => (
                      <SelectItem key={t.type} value={t.type}>{t.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.name')}</label>
                <Input value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder={t('pages.pamConnections.entryDialog.namePlaceholder')} />
              </div>
            </div>

            {selectedType?.protocol && (
              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.hostname')}</label>
                  <Input value={form.hostname} onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))} placeholder={t('pages.pamConnections.entryDialog.hostnamePlaceholder')} />
                </div>
                <div>
                  <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.port')}</label>
                  <Input type="number" value={form.port || ''} onChange={(e) => setForm((f) => ({ ...f, port: Number(e.target.value) }))} placeholder={t('pages.pamConnections.entryDialog.portPlaceholder')} />
                </div>
              </div>
            )}

            {form.entry_type === 'website' && (
              <div>
                <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.url')}</label>
                <Input value={form.url} onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))} placeholder="https://portal.corp" />
              </div>
            )}

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.username')}</label>
                <Input value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} placeholder={t('pages.pamConnections.entryDialog.usernamePlaceholder')} />
              </div>
              {form.entry_type === 'rdp' && (
                <div>
                  <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.domain')}</label>
                  <Input value={form.domain} onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))} placeholder={t('pages.pamConnections.entryDialog.domainPlaceholder')} />
                </div>
              )}
            </div>

            {form.entry_type === 'rdp' && (
              <div className="rounded-md border p-3 space-y-3">
                <div>
                  <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.securityMode')}</label>
                  <p className="text-xs text-muted-foreground">
                    {t('pages.pamConnections.entryDialog.securityHintBefore')}
                    <strong>{t('pages.pamConnections.entryDialog.securityHintStrong')}</strong>
                    {t('pages.pamConnections.entryDialog.securityHintAfter')}
                  </p>
                  <Select
                    value={settingStr('security') || 'default'}
                    onValueChange={(v) => setSetting('security', v === 'default' ? '' : v)}
                  >
                    <SelectTrigger aria-label={t('pages.pamConnections.entryDialog.securityModeLabel')}><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="default">{t('pages.pamConnections.entryDialog.securityDefault')}</SelectItem>
                      <SelectItem value="any">{t('pages.pamConnections.entryDialog.securityAny')}</SelectItem>
                      <SelectItem value="nla">NLA</SelectItem>
                      <SelectItem value="tls">TLS</SelectItem>
                      <SelectItem value="rdp">{t('pages.pamConnections.entryDialog.securityStandard')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <p className="text-sm font-medium">{t('pages.pamConnections.entryDialog.remoteAppTitle')}</p>
                  <p className="text-xs text-muted-foreground">
                    {t('pages.pamConnections.entryDialog.remoteAppHint')}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.preset')}</label>
                  <Select
                    value="custom"
                    onValueChange={(v) => {
                      const preset = remoteAppPresets.find((p) => p.alias === v)
                      if (!preset) return
                      setForm((f) => ({
                        ...f,
                        settings: {
                          ...(f.settings || {}),
                          'remote-app': `||${preset.alias}`,
                          ...(preset.args ? { 'remote-app-args': preset.args } : {}),
                        },
                      }))
                    }}
                  >
                    <SelectTrigger aria-label={t('pages.pamConnections.entryDialog.presetPlaceholder')}>
                      <SelectValue placeholder={t('pages.pamConnections.entryDialog.presetPlaceholder')} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="custom">{t('pages.pamConnections.entryDialog.presetCustom')}</SelectItem>
                      {remoteAppPresets.map((p) => (
                        <SelectItem key={p.alias} value={p.alias}>{p.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.programAlias')}</label>
                    <Input
                      value={settingStr('remote-app').replace(/^\|\|/, '')}
                      onChange={(e) => setRemoteAppAlias(e.target.value)}
                      placeholder="SSMS"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.workingDirectory')}</label>
                    <Input
                      value={settingStr('remote-app-dir')}
                      onChange={(e) => setSetting('remote-app-dir', e.target.value)}
                      placeholder="C:\Users\Public"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium">{t('pages.pamConnections.entryDialog.args')}</label>
                  <Input
                    value={settingStr('remote-app-args')}
                    onChange={(e) => setSetting('remote-app-args', e.target.value)}
                    placeholder="-S sql01.corp.local -E"
                    aria-invalid={remoteAppArgsLookSecret(settingStr('remote-app-args'))}
                    className={remoteAppArgsLookSecret(settingStr('remote-app-args')) ? 'border-destructive' : undefined}
                  />
                  {remoteAppArgsLookSecret(settingStr('remote-app-args')) && (
                    <p className="mt-1 flex items-start gap-1.5 text-xs text-destructive">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-px" />
                      <span>{remoteAppSecretHint()}</span>
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Credential: own secret or linked credential entry */}
            {selectedType?.kind === 'session' && credentialEntries.length > 0 && (
              <div>
                <label htmlFor="pam-connections-linked-credential" className="text-sm font-medium">{t('pages.pamConnections.entryDialog.linkedCredential')}</label>
                <Select
                  value={form.credential_entry_id || 'none'}
                  onValueChange={(v) => setForm((f) => ({ ...f, credential_entry_id: v === 'none' ? '' : v }))}
                >
                  <SelectTrigger id="pam-connections-linked-credential">
                    <SelectValue placeholder={t('pages.pamConnections.entryDialog.ownSecret')} />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">{t('pages.pamConnections.entryDialog.ownSecret')}</SelectItem>
                    {credentialEntries.map((c) => (
                      <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {!form.credential_entry_id && (
              <div>
                <label className="text-sm font-medium">
                  {selectedType?.secret_label || t('pages.pamConnections.entryDialog.secret')}
                  {editingId ? t('pages.pamConnections.entryDialog.secretKeepCurrent') : ''}
                </label>
                <Textarea
                  value={form.secret}
                  onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
                  placeholder={t('pages.pamConnections.entryDialog.secretPlaceholder')}
                  rows={form.entry_type === 'ssh_key' ? 4 : 2}
                />
              </div>
            )}

            <div>
              <label htmlFor="pam-connections-description" className="text-sm font-medium">{t('pages.pamConnections.entryDialog.description')}</label>
              <Input id="pam-connections-description" value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
            </div>

            <div className="flex flex-wrap gap-4 pt-2">
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.allow_reveal} onCheckedChange={(v) => setForm((f) => ({ ...f, allow_reveal: !!v }))} />
                {t('pages.pamConnections.entryDialog.allowReveal')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.require_approval} onCheckedChange={(v) => setForm((f) => ({ ...f, require_approval: !!v }))} />
                {t('pages.pamConnections.entryDialog.requireApproval')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <Checkbox checked={form.record_session} onCheckedChange={(v) => setForm((f) => ({ ...f, record_session: !!v }))} />
                {t('pages.pamConnections.entryDialog.recordSession')}
              </label>
            </div>
            {selectedType?.protocol === 'ssh' && (
              <label className="flex items-center gap-2 text-sm pt-1">
                <Checkbox
                  checked={form.renderer === 'wasm-ssh'}
                  onCheckedChange={(v) => setForm((f) => ({ ...f, renderer: v ? 'wasm-ssh' : 'guacamole' }))}
                />
                {t('pages.pamConnections.entryDialog.browserTerminal')}
              </label>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowEntryDialog(false)}>
              {t('common.cancel')}
            </Button>
            <Button
              onClick={() => saveEntry.mutate()}
              disabled={saveEntry.isPending || !form.name || remoteAppArgsLookSecret(settingStr('remote-app-args'))}
            >
              {editingId
                ? t('pages.pamConnections.entryDialog.save')
                : t('pages.pamConnections.entryDialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Connection path explainer: the launch chain with this entry's real config */}
      <Dialog open={!!pathEntry} onOpenChange={(o) => { if (!o) setPathEntry(null) }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>
              {t('pages.pamConnections.pathDialog.title', { name: pathEntry?.name ?? '' })}
            </DialogTitle>
          </DialogHeader>
          {pathEntry && (
            <div>
              {connectionPathSteps(pathEntry).map((step, i, arr) => {
                const StepIcon = step.icon
                return (
                  <div key={i} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className="rounded-full border p-1.5 bg-muted/40">
                        <StepIcon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      {i < arr.length - 1 && <div className="w-px flex-1 bg-border my-1" />}
                    </div>
                    <div className="pb-4 min-w-0">
                      <p className="text-sm font-medium">{step.title}</p>
                      <p className="text-xs text-muted-foreground">{step.desc}</p>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* New folder dialog */}
      <Dialog open={showFolderDialog} onOpenChange={setShowFolderDialog}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('pages.pamConnections.folderDialog.title')}</DialogTitle></DialogHeader>
          <Input value={folderName} onChange={(e) => setFolderName(e.target.value)} placeholder={t('pages.pamConnections.folderDialog.placeholder')} />
          {selectedFolder && <p className="text-xs text-muted-foreground">{t('pages.pamConnections.folderDialog.underSelected')}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowFolderDialog(false)}>{t('common.cancel')}</Button>
            <Button onClick={() => createFolder.mutate()} disabled={!folderName || createFolder.isPending}>
              {t('pages.pamConnections.folderDialog.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* RDM import dialog */}
      <Dialog open={showImport} onOpenChange={setShowImport}>
        <DialogContent className="max-w-2xl">
          <DialogHeader><DialogTitle>{t('pages.pamConnections.importDialog.title')}</DialogTitle></DialogHeader>
          {importResult ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-green-600"><ShieldCheck className="h-5 w-5" /> {t('pages.pamConnections.importDialog.complete')}</div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <Card><CardContent className="py-3"><div className="text-2xl font-bold">{importResult.entries_created}</div><div className="text-xs text-muted-foreground">{t('pages.pamConnections.importDialog.entries')}</div></CardContent></Card>
                <Card><CardContent className="py-3"><div className="text-2xl font-bold">{importResult.folders_created}</div><div className="text-xs text-muted-foreground">{t('pages.pamConnections.importDialog.folders')}</div></CardContent></Card>
                <Card><CardContent className="py-3"><div className="text-2xl font-bold">{importResult.secrets_stored}</div><div className="text-xs text-muted-foreground">{t('pages.pamConnections.importDialog.secrets')}</div></CardContent></Card>
              </div>
              {Object.keys(importResult.by_type).length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(importResult.by_type).map(([t, n]) => (
                    <Badge key={t} variant="outline">{t}: {n}</Badge>
                  ))}
                </div>
              )}
              {importResult.skipped.length > 0 && (
                <div className="text-xs text-muted-foreground">
                  {t('pages.pamConnections.importDialog.skipped', {
                    count: importResult.skipped.length,
                    names: importResult.skipped.slice(0, 5).map((s) => s.name).join(', '),
                  })}
                  {importResult.skipped.length > 5 ? '…' : ''}
                </div>
              )}
              <DialogFooter>
                <Button onClick={() => setShowImport(false)}>{t('pages.pamConnections.importDialog.done')}</Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                {t('pages.pamConnections.importDialog.instructionsBefore')}
                <strong>{t('pages.pamConnections.importDialog.instructionsExport')}</strong>
                {t('pages.pamConnections.importDialog.instructionsMiddle')}
                <strong>{t('pages.pamConnections.importDialog.instructionsFormat')}</strong>
                {t('pages.pamConnections.importDialog.instructionsAfter')}
              </p>
              <Textarea
                value={importData}
                onChange={(e) => setImportData(e.target.value)}
                placeholder='{"Connections":[ … ]}'
                rows={10}
                className="font-mono text-xs"
              />
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowImport(false)}>{t('common.cancel')}</Button>
                <Button onClick={() => runImport.mutate()} disabled={!importData || runImport.isPending}>
                  <Upload className="h-4 w-4 mr-1" /> {t('pages.pamConnections.importDialog.submit')}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Reveal dialog */}
      <Dialog open={!!revealFor} onOpenChange={(o) => { if (!o) { clearRevealed(); setRevealFor(null) } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('pages.pamConnections.revealDialog.title', { name: revealFor?.name ?? '' })}
            </DialogTitle>
          </DialogHeader>
          {revealedValue === null ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">{t('pages.pamConnections.revealDialog.audited')}</p>
              <Textarea value={revealReason} onChange={(e) => setRevealReason(e.target.value)} placeholder={t('pages.pamConnections.revealDialog.reasonPlaceholder')} rows={2} />
              <DialogFooter>
                <Button variant="outline" onClick={() => { clearRevealed(); setRevealFor(null) }}>
                  {t('common.cancel')}
                </Button>
                <Button onClick={() => reveal.mutate()} disabled={!revealReason || reveal.isPending}>
                  <Eye className="h-4 w-4 mr-1" /> {t('pages.pamConnections.revealDialog.submit')}
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Input aria-label={t('common.revealedValue')} readOnly value={revealedValue} className="font-mono" />
                <Button size="sm" variant="outline" onClick={async () => {
                  const ok = await copyWithWarning(revealedValue)
                  if (ok) {
                    toast({ title: t('common.copied'), description: t('pages.pamConnections.toasts.copied') })
                  } else {
                    toast({
                      title: t('pages.pamConnections.toasts.copyFailedTitle'),
                      description: t('pages.pamConnections.toasts.copyFailed'),
                      variant: 'destructive',
                    })
                  }
                }}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <DialogFooter>
                <Button onClick={() => { clearRevealed(); setRevealFor(null) }}>{t('common.close')}</Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Request access dialog */}
      <Dialog open={!!requestFor} onOpenChange={(o) => { if (!o) setRequestFor(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {t('pages.pamConnections.requestDialog.title', { name: requestFor?.name ?? '' })}
            </DialogTitle>
          </DialogHeader>
          <Textarea value={requestReason} onChange={(e) => setRequestReason(e.target.value)} placeholder={t('pages.pamConnections.requestDialog.reasonPlaceholder')} rows={3} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setRequestFor(null)}>{t('common.cancel')}</Button>
            <Button onClick={() => requestAccess.mutate()} disabled={requestAccess.isPending}>
              <Send className="h-4 w-4 mr-1" /> {t('pages.pamConnections.requestDialog.submit')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <AlertDialog open={!!deleteEntry} onOpenChange={(o) => { if (!o) setDeleteEntry(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('pages.pamConnections.confirmDelete.title', { name: deleteEntry?.name ?? '' })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t('pages.pamConnections.confirmDelete.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteEntry && del.mutate(deleteEntry.id)}>
              {t('common.delete')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Clientless in-browser SSH terminal (wasm-ssh renderer). */}
      <Dialog open={!!terminalEntry} onOpenChange={(o) => { if (!o) setTerminalEntry(null) }}>
        <DialogContent className="max-w-4xl p-0 overflow-hidden">
          {terminalEntry && (
            <TerminalSession
              entryId={terminalEntry.id}
              entryName={terminalEntry.name}
              onClose={() => setTerminalEntry(null)}
            />
          )}
        </DialogContent>
      </Dialog>

    </div>
  )
}
