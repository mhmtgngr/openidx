import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Copy, KeyRound, Plus, Trash2 } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from './ui/alert-dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs'
import { LoadingSpinner } from './ui/loading-spinner'
import { QueryError } from './query-error'
import { api, baseURL } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { INSTALL_TARGETS, installCommands, type InstallTarget } from '../lib/agent-install-commands'

// A fleet token as GET /agent/tokens lists it (never the plaintext).
export interface EnrollmentTokenRecord {
  id: string
  name: string
  description: string
  created_at: string
  expires_at: string
  used_at: string | null
  revoked: boolean
  reusable: boolean
  max_uses: number | null
  uses: number
  default_tags: string[]
  last_used_at: string | null
}

interface MintedToken {
  id: string
  token: string
  name: string
  expires_at: string
}

const TTL_DAYS = [7, 30, 90, 180, 365]

function serverURL(): string {
  return (baseURL || window.location.origin).replace(/\/+$/, '')
}

// FleetTokensSection lists, mints and revokes the reusable enrollment tokens
// a rollout (Intune, GPO, a script) installs the agent with. The plaintext is
// shown once, in the Deploy panel, right after the mint.
export function FleetTokensSection() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [mintOpen, setMintOpen] = useState(false)
  const [name, setName] = useState('')
  const [ttlDays, setTtlDays] = useState(90)
  const [maxUses, setMaxUses] = useState('')
  const [tags, setTags] = useState('')
  const [minted, setMinted] = useState<MintedToken | null>(null)
  const [confirmRevoke, setConfirmRevoke] = useState<EnrollmentTokenRecord | null>(null)

  const { data: tokens = [], isLoading, isError, error } = useQuery({
    queryKey: ['agent-tokens'],
    queryFn: () => api.get<EnrollmentTokenRecord[]>('/api/v1/access/agent/tokens'),
  })
  const fleet = tokens.filter((tk) => tk.reusable)

  const mint = useMutation({
    mutationFn: () =>
      api.post<MintedToken>('/api/v1/access/agent/tokens', {
        reusable: true,
        name: name.trim(),
        ttl_hours: Math.min(ttlDays * 24, 8760),
        max_uses: maxUses.trim() ? Number(maxUses) : 0,
        default_tags: tags.split(',').map((s) => s.trim()).filter(Boolean),
      }),
    onSuccess: (data) => {
      setMinted(data)
      queryClient.invalidateQueries({ queryKey: ['agent-tokens'] })
    },
    onError: () => toast({ title: t('pages.agentFleet.tokens.mintFailed'), variant: 'destructive' }),
  })

  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/v1/access/agent/tokens/${id}`),
    onSuccess: () => {
      setConfirmRevoke(null)
      queryClient.invalidateQueries({ queryKey: ['agent-tokens'] })
      toast({ title: t('pages.agentFleet.tokens.revoked') })
    },
    onError: () => toast({ title: t('pages.agentFleet.tokens.revokeFailed'), variant: 'destructive' }),
  })

  function openMint() {
    setName('')
    setTtlDays(90)
    setMaxUses('')
    setTags('')
    setMinted(null)
    setMintOpen(true)
  }

  function status(tk: EnrollmentTokenRecord): { label: string; variant: 'success' | 'secondary' | 'destructive' | 'warning' } {
    if (tk.revoked) return { label: t('pages.agentFleet.tokens.statusRevoked'), variant: 'destructive' }
    if (new Date(tk.expires_at).getTime() <= Date.now()) return { label: t('pages.agentFleet.tokens.statusExpired'), variant: 'secondary' }
    if (tk.max_uses !== null && tk.uses >= tk.max_uses) return { label: t('pages.agentFleet.tokens.statusExhausted'), variant: 'warning' }
    return { label: t('pages.agentFleet.tokens.statusActive'), variant: 'success' }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2"><KeyRound className="h-5 w-5" /> {t('pages.agentFleet.tokens.heading')}</CardTitle>
          <p className="text-sm text-muted-foreground">{t('pages.agentFleet.tokens.intro')}</p>
        </div>
        <Button onClick={openMint}><Plus className="mr-2 h-4 w-4" /> {t('pages.agentFleet.tokens.mint')}</Button>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <LoadingSpinner />
        ) : isError ? (
          <QueryError error={error} resource={t('pages.agentFleet.tokens.resource')} />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('pages.agentFleet.tokens.colName')}</TableHead>
                <TableHead>{t('pages.agentFleet.tokens.colUses')}</TableHead>
                <TableHead>{t('pages.agentFleet.tokens.colTags')}</TableHead>
                <TableHead>{t('pages.agentFleet.tokens.colExpires')}</TableHead>
                <TableHead>{t('pages.agentFleet.tokens.colLastUsed')}</TableHead>
                <TableHead>{t('pages.agentFleet.tokens.colStatus')}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {fleet.map((tk) => {
                const st = status(tk)
                return (
                  <TableRow key={tk.id}>
                    <TableCell className="font-medium">{tk.name || tk.description || tk.id.slice(0, 8)}</TableCell>
                    <TableCell>{tk.max_uses === null ? `${tk.uses}` : `${tk.uses} / ${tk.max_uses}`}</TableCell>
                    <TableCell className="space-x-1">
                      {(tk.default_tags ?? []).map((tag) => <Badge key={tag} variant="secondary">{tag}</Badge>)}
                    </TableCell>
                    <TableCell>{new Date(tk.expires_at).toLocaleDateString()}</TableCell>
                    <TableCell>{tk.last_used_at ? new Date(tk.last_used_at).toLocaleString() : '—'}</TableCell>
                    <TableCell><Badge variant={st.variant as any}>{st.label}</Badge></TableCell>
                    <TableCell className="text-right">
                      {!tk.revoked && (
                        <Button variant="ghost" size="sm" aria-label={t('pages.agentFleet.tokens.revoke')} onClick={() => setConfirmRevoke(tk)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
              {fleet.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-muted-foreground">{t('pages.agentFleet.tokens.empty')}</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <Dialog open={mintOpen} onOpenChange={setMintOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{minted ? t('pages.agentFleet.deploy.title') : t('pages.agentFleet.tokens.mintTitle')}</DialogTitle>
          </DialogHeader>
          {minted ? (
            <DeployPanel token={minted.token} expiresAt={minted.expires_at} />
          ) : (
            <div className="space-y-3">
              <div className="space-y-1">
                <label htmlFor="fleet-token-name" className="text-sm font-medium">{t('pages.agentFleet.tokens.name')}</label>
                <Input id="fleet-token-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={t('pages.agentFleet.tokens.namePlaceholder')} />
              </div>
              <div className="space-y-1">
                <label htmlFor="fleet-token-ttl" className="text-sm font-medium">{t('pages.agentFleet.tokens.ttl')}</label>
                <select id="fleet-token-ttl" className="h-9 w-full rounded-md border bg-background px-2 text-sm" value={ttlDays} onChange={(e) => setTtlDays(Number(e.target.value))}>
                  {TTL_DAYS.map((d) => <option key={d} value={d}>{t('pages.agentFleet.tokens.days', { count: d })}</option>)}
                </select>
              </div>
              <div className="space-y-1">
                <label htmlFor="fleet-token-max" className="text-sm font-medium">{t('pages.agentFleet.tokens.maxUses')}</label>
                <Input id="fleet-token-max" type="number" min={1} value={maxUses} onChange={(e) => setMaxUses(e.target.value)} placeholder={t('pages.agentFleet.tokens.maxUsesPlaceholder')} />
              </div>
              <div className="space-y-1">
                <label htmlFor="fleet-token-tags" className="text-sm font-medium">{t('pages.agentFleet.tokens.tags')}</label>
                <Input id="fleet-token-tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder={t('pages.agentFleet.tokens.tagsPlaceholder')} />
              </div>
            </div>
          )}
          <DialogFooter>
            {minted ? (
              <Button onClick={() => setMintOpen(false)}>{t('pages.agentFleet.deploy.done')}</Button>
            ) : (
              <>
                <Button variant="outline" onClick={() => setMintOpen(false)}>{t('common.cancel')}</Button>
                <Button onClick={() => mint.mutate()} disabled={mint.isPending}>{t('pages.agentFleet.tokens.mint')}</Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={!!confirmRevoke} onOpenChange={(o) => !o && setConfirmRevoke(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('pages.agentFleet.tokens.revokeTitle')}</AlertDialogTitle>
            <AlertDialogDescription>{t('pages.agentFleet.tokens.revokeBody')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
            <AlertDialogAction onClick={() => confirmRevoke && revoke.mutate(confirmRevoke.id)}>{t('pages.agentFleet.tokens.revoke')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

// DeployPanel shows the one-time token and the commands that install the
// agent with it. It is rendered only from the mint response.
export function DeployPanel({ token, expiresAt }: { token: string; expiresAt: string }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [tab, setTab] = useState<InstallTarget>('intune')
  const server = serverURL()
  function copy(v: string) {
    navigator.clipboard.writeText(v)
    toast({ title: t('pages.agentFleet.toasts.copied') })
  }
  return (
    <div className="space-y-3">
      <p className="text-sm text-amber-700">{t('pages.agentFleet.deploy.onceWarning')}</p>
      <div className="flex items-center gap-2 rounded border bg-muted p-2 font-mono text-xs">
        <span className="break-all">{token}</span>
        <Button variant="ghost" size="sm" aria-label={t('pages.agentFleet.deploy.copy')} onClick={() => copy(token)}><Copy className="h-4 w-4" /></Button>
      </div>
      <p className="text-xs text-muted-foreground">{t('pages.agentFleet.deploy.expires', { when: new Date(expiresAt).toLocaleString() })}</p>
      <Tabs value={tab} onValueChange={(v) => setTab(v as InstallTarget)}>
        <TabsList>
          {INSTALL_TARGETS.map((tg) => <TabsTrigger key={tg} value={tg}>{t(`pages.agentFleet.deploy.tabs.${tg}`)}</TabsTrigger>)}
        </TabsList>
        {INSTALL_TARGETS.map((tg) => (
          <TabsContent key={tg} value={tg} className="space-y-2">
            <p className="text-sm text-muted-foreground">{t(`pages.agentFleet.deploy.hints.${tg}`)}</p>
            {installCommands(tg, { serverUrl: server, token }).map((cmd) => (
              <div key={cmd.label} className="space-y-1">
                <div className="text-xs font-medium">{t(`pages.agentFleet.deploy.steps.${cmd.label}`)}</div>
                <div className="flex items-start gap-2 rounded border bg-muted p-2 font-mono text-xs">
                  <code className="flex-1 whitespace-pre-wrap break-all">{cmd.value}</code>
                  <Button variant="ghost" size="sm" aria-label={t('pages.agentFleet.deploy.copy')} onClick={() => copy(cmd.value)}><Copy className="h-4 w-4" /></Button>
                </div>
              </div>
            ))}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  )
}
