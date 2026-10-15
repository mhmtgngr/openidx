import { useTranslation } from 'react-i18next'
import { Badge } from './ui/badge'

/** The OpenZiti tunneler state an agent last reported (GET /api/v1/access/agents). */
export interface TunnelStatus {
  state: string
  version?: string
  last_seen?: string
  services?: { name: string; status?: string; dial_failures?: number }[]
  dial_failures?: number
  /** How the device applied the organization's tunnel policy. */
  mode?: string
  policy_version?: string
  policy_gaps?: string[]
  last_error?: string
}

const KNOWN_STATES = ['up', 'down', 'starting', 'stopped', 'off', 'not_installed', 'unknown'] as const
const KNOWN_GAPS = ['full_tunnel', 'block_direct'] as const

/**
 * TunnelStatusBadge shows a device's tunnel state on the Agent Fleet page. Its
 * title carries the version, how many services the tunneler had, when the
 * server last heard it was up (tunnel_last_seen, the server's clock), the mode
 * it routes in, what of the tunnel policy it cannot enforce, and its last
 * error.
 */
export function TunnelStatusBadge({ status, lastSeen }: { status?: TunnelStatus | null; lastSeen?: string | null }) {
  const { t } = useTranslation()
  if (!status) {
    return <span className="text-xs text-muted-foreground">{t('pages.agentFleet.tunnelNone')}</span>
  }
  const state = (KNOWN_STATES as readonly string[]).includes(status.state) ? status.state : 'unknown'
  const variant = state === 'up' ? 'success' : state === 'down' || state === 'stopped' ? 'destructive' : 'outline'
  const lines = [
    t('pages.agentFleet.tunnelDetail', {
      version: status.version || '—',
      count: status.services?.length ?? 0,
      when: lastSeen ? new Date(lastSeen).toLocaleString() : t('pages.agentFleet.tunnelNeverUp'),
    }),
  ]
  if (status.mode) lines.push(t('pages.agentFleet.tunnelMode', { mode: status.mode }))
  const gaps = (status.policy_gaps ?? []).filter((g) => (KNOWN_GAPS as readonly string[]).includes(g))
  if (gaps.length > 0) {
    lines.push(
      t('pages.agentFleet.tunnelGaps', {
        gaps: gaps.map((g) => t(`pages.agentFleet.tunnelGapNames.${g}`)).join(', '),
      }),
    )
  }
  if (status.last_error) lines.push(t('pages.agentFleet.tunnelLastError', { error: status.last_error }))
  return (
    <Badge variant={variant} title={lines.join('\n')} data-testid="tunnel-status">
      {t(`pages.agentFleet.tunnelStates.${state}`)}
    </Badge>
  )
}

const POLICY_STATES = ['applied', 'applied_with_gaps', 'pending'] as const

/**
 * TunnelPolicyBadge says whether a device runs the organization's current
 * tunnel policy (tunnel_policy_state from GET /api/v1/access/agents): applied,
 * applied with gaps (the current version, with a part of it the device cannot
 * enforce, named on the tunnel badge), or pending until its agent next
 * reports. Nothing for a device that reports no tunnel status. A device with
 * gaps is never shown as applied: what the page says is what is enforced.
 */
export function TunnelPolicyBadge({
  state,
  version,
  appliedAt,
}: {
  state?: string | null
  version?: string | null
  appliedAt?: string | null
}) {
  const { t } = useTranslation()
  if (!state || !(POLICY_STATES as readonly string[]).includes(state)) return null
  const title =
    state === 'pending'
      ? t('pages.agentFleet.policyPendingDetail', { version: version || '—' })
      : t(state === 'applied' ? 'pages.agentFleet.policyAppliedDetail' : 'pages.agentFleet.policyAppliedWithGapsDetail', {
          version: version || '—',
          when: appliedAt ? new Date(appliedAt).toLocaleString() : '—',
        })
  return (
    <Badge
      variant={state === 'applied' ? 'outline' : 'warning'}
      title={title}
      data-testid="tunnel-policy"
      data-state={state}
      className="whitespace-nowrap"
    >
      {t(`pages.agentFleet.policyStates.${state}`)}
    </Badge>
  )
}
