import { useTranslation } from 'react-i18next'
import { Badge } from './ui/badge'

/** The OpenZiti tunneler state an agent last reported (GET /api/v1/access/agents). */
export interface TunnelStatus {
  state: string
  version?: string
  last_seen?: string
  services?: { name: string; status?: string; dial_failures?: number }[]
  dial_failures?: number
}

const KNOWN_STATES = ['up', 'down', 'starting', 'stopped', 'not_installed', 'unknown'] as const

/**
 * TunnelStatusBadge shows a device's tunnel state on the Agent Fleet page. Its
 * title carries the version, how many services the tunneler had and when the
 * server last heard it was up (tunnel_last_seen, the server's clock).
 */
export function TunnelStatusBadge({ status, lastSeen }: { status?: TunnelStatus | null; lastSeen?: string | null }) {
  const { t } = useTranslation()
  if (!status) {
    return <span className="text-xs text-muted-foreground">{t('pages.agentFleet.tunnelNone')}</span>
  }
  const state = (KNOWN_STATES as readonly string[]).includes(status.state) ? status.state : 'unknown'
  const variant = state === 'up' ? 'success' : state === 'down' || state === 'stopped' ? 'destructive' : 'outline'
  const title = t('pages.agentFleet.tunnelDetail', {
    version: status.version || '—',
    count: status.services?.length ?? 0,
    when: lastSeen ? new Date(lastSeen).toLocaleString() : t('pages.agentFleet.tunnelNeverUp'),
  })
  return (
    <Badge variant={variant} title={title} data-testid="tunnel-status">
      {t(`pages.agentFleet.tunnelStates.${state}`)}
    </Badge>
  )
}
