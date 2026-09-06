import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation } from '@tanstack/react-query'
import * as Icons from 'lucide-react'
import { ExternalLink, Link2, Play } from 'lucide-react'
import { Card, CardContent } from './ui/card'
import { Badge } from './ui/badge'
import { Dialog, DialogContent } from './ui/dialog'
import { api, QuickLink } from '../lib/api'
import { QueryError } from './query-error'
import { useToast } from '../hooks/use-toast'
import { TerminalSession } from './remote/terminal-session'

// Resolve a lucide icon by name (admin picks one); fall back to Link2.
function iconFor(name: string) {
  const C = (Icons as unknown as Record<string, React.ComponentType<{ className?: string }>>)[name]
  return C || Link2
}

/**
 * QuickLinksSection is the "Quick links" block of the combined My Apps & Network
 * page: admin-curated shortcuts (support/collaboration URLs + one-click PAM
 * connections), grouped by category. The caller owns the shared search box; the
 * section hides itself when the user has no quick links.
 */
export function QuickLinksSection({ search }: { search: string }) {
  const { t } = useTranslation()
  const [terminalLink, setTerminalLink] = useState<QuickLink | null>(null)
  const { toast } = useToast()

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['quick-links-mine'],
    queryFn: () => api.quickLinks.listMine(),
  })

  const connect = useMutation({
    mutationFn: (id: string) => api.pam.connect(id),
    onSuccess: (res) => {
      const url = res.connect_url || res.url
      if (url) window.open(url, '_blank', 'noopener')
      else toast({ title: t('components.quickLinks.nothingToLaunch'), variant: 'destructive' })
    },
    onError: (e: Error & { body?: { approval_required?: boolean } }) => {
      if (e.body?.approval_required || /requires approval/i.test(e.message)) {
        toast({ title: t('components.quickLinks.approvalRequired'), description: t('components.quickLinks.approvalRequiredDesc'), variant: 'destructive' })
      } else {
        toast({ title: t('components.quickLinks.launchFailed'), description: e.message, variant: 'destructive' })
      }
    },
  })

  const open = (link: QuickLink) => {
    if (link.type === 'external' && link.url) {
      if (link.open_in_new) window.open(link.url, '_blank', 'noopener')
      else window.location.assign(link.url)
      return
    }
    if (link.type === 'pam' && link.pam_entry_id) {
      // Clientless: wasm-ssh opens the in-browser terminal; else the guac/URL flow.
      if (link.pam_renderer === 'wasm-ssh') setTerminalLink(link)
      else connect.mutate(link.pam_entry_id)
    }
  }

  const term = search.trim().toLowerCase()
  const all = data?.quick_links || []
  const links = all.filter((l) =>
    !term ||
    l.title.toLowerCase().includes(term) ||
    l.description.toLowerCase().includes(term) ||
    l.category.toLowerCase().includes(term),
  )

  // Group by category for a scannable layout.
  const grouped = useMemo(() => {
    const g: Record<string, QuickLink[]> = {}
    for (const l of links) (g[l.category] ||= []).push(l)
    return Object.entries(g).sort(([a], [b]) => a.localeCompare(b))
  }, [links])

  // Hide the whole section when the user has no quick links at all.
  if (!isLoading && !isError && all.length === 0) {
    return null
  }

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">{t('components.quickLinks.heading')}</h2>
        <p className="text-sm text-muted-foreground">
          {t('components.quickLinks.subtitle')}
        </p>
      </div>

      {isLoading ? (
        <p className="text-center py-8 text-muted-foreground">{t('common.loading')}</p>
      ) : isError ? (
        <QueryError error={error} resource={t('components.quickLinks.resource')} />
      ) : links.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('components.quickLinks.noMatch', { search })}</p>
      ) : (
        grouped.map(([category, items]) => (
          <div key={category} className="space-y-3">
            <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{category}</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {items.map((link) => {
                const Icon = iconFor(link.icon)
                return (
                  <Card key={link.id} className="hover:shadow-lg transition-shadow cursor-pointer group" onClick={() => open(link)}>
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center shrink-0">
                          <Icon className="h-5 w-5 text-primary" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="font-medium truncate">{link.title}</p>
                            {link.type === 'pam' ? (
                              <Badge variant="secondary" className="text-xs">{t(link.pam_renderer === 'wasm-ssh' ? 'components.quickLinks.kindTerminal' : 'components.quickLinks.kindConnect')}</Badge>
                            ) : (
                              <Badge variant="outline" className="text-xs">{t('components.quickLinks.kindLink')}</Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground line-clamp-2 mt-1">{link.description || ' '}</p>
                          <div className="mt-2 text-sm text-primary flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            {link.type === 'pam'
                              ? <><Play className="h-3.5 w-3.5" /> {t('components.quickLinks.launch')}</>
                              : <><ExternalLink className="h-3.5 w-3.5" /> {t('components.quickLinks.open')}</>}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        ))
      )}

      {/* Clientless in-browser SSH terminal for wasm-ssh PAM quick links. */}
      <Dialog open={!!terminalLink} onOpenChange={(o) => { if (!o) setTerminalLink(null) }}>
        <DialogContent className="max-w-4xl p-0 overflow-hidden">
          {terminalLink?.pam_entry_id && (
            <TerminalSession entryId={terminalLink.pam_entry_id} entryName={terminalLink.title} onClose={() => setTerminalLink(null)} />
          )}
        </DialogContent>
      </Dialog>
    </section>
  )
}
