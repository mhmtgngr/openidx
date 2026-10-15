// The network-target form helpers of the network-resources panel: the API shapes
// and the conversion between a stored target and its editable draft.

export interface PortRange {
  low: number
  high: number
}

export interface NetworkTarget {
  hosts: string[]
  cidrs: string[]
  dns_names: string[]
  port_ranges: PortRange[]
  protocols: string[]
  forward_address?: string
  forward_port?: number
}

export interface NetworkResource {
  id: string
  name: string
  description: string
  enabled: boolean
  service_name: string
  target: NetworkTarget | null
  sync_status?: string
}

export interface NetworkPolicy {
  always_on: boolean
  split_tunnel: boolean
  block_direct_corporate_cidrs: boolean
  updated_at?: string
  /** The version devices receive; read-only. */
  version?: string
  /**
   * Active devices by whether they report applying that version; read-only.
   * applied_with_gaps are on the current version with a part of it they
   * cannot enforce (and are not counted as applied).
   */
  devices?: { applied: number; applied_with_gaps?: number; pending: number; unreported: number }
}

/** The editable form of a target: lists as text, one entry per line or comma. */
export interface TargetDraft {
  hosts: string
  cidrs: string
  dns_names: string
  ports: string
  tcp: boolean
  udp: boolean
  forward_address: string
  forward_port: string
}

export const EMPTY_DRAFT: TargetDraft = {
  hosts: '', cidrs: '', dns_names: '', ports: '', tcp: true, udp: true, forward_address: '', forward_port: '',
}

const splitList = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean)

export function formatPorts(ranges: PortRange[]): string {
  if (ranges.length === 1 && ranges[0].low === 1 && ranges[0].high === 65535) return ''
  return ranges.map((r) => (r.low === r.high ? `${r.low}` : `${r.low}-${r.high}`)).join(', ')
}

export function draftFromTarget(t: NetworkTarget | null | undefined): TargetDraft {
  if (!t) return EMPTY_DRAFT
  return {
    hosts: t.hosts.join('\n'),
    cidrs: t.cidrs.join('\n'),
    dns_names: t.dns_names.join('\n'),
    ports: formatPorts(t.port_ranges),
    tcp: t.protocols.includes('tcp'),
    udp: t.protocols.includes('udp'),
    forward_address: t.forward_address ?? '',
    forward_port: t.forward_port ? String(t.forward_port) : '',
  }
}

/**
 * targetFromDraft turns the form into the API's target, or returns the key of
 * the first client-side problem. The server validates everything again
 * (CIDR parsing, port bounds); this only catches what a typo makes obvious.
 */
export function targetFromDraft(d: TargetDraft): { target?: NetworkTarget; error?: string } {
  const hosts = splitList(d.hosts)
  const cidrs = splitList(d.cidrs)
  const dns_names = splitList(d.dns_names)
  if (hosts.length + cidrs.length + dns_names.length === 0) return { error: 'needAddress' }
  const port_ranges: PortRange[] = []
  for (const p of splitList(d.ports)) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p)
    if (!m) return { error: 'badPort' }
    const low = Number(m[1])
    const high = m[2] ? Number(m[2]) : low
    if (low < 1 || high > 65535 || low > high) return { error: 'badPort' }
    port_ranges.push({ low, high })
  }
  const protocols = [d.tcp && 'tcp', d.udp && 'udp'].filter(Boolean) as string[]
  if (protocols.length === 0) return { error: 'needProtocol' }
  let forward_port: number | undefined
  if (d.forward_port.trim() !== '') {
    forward_port = Number(d.forward_port)
    if (!Number.isInteger(forward_port) || forward_port < 1 || forward_port > 65535) return { error: 'badPort' }
  }
  return {
    target: {
      hosts, cidrs, dns_names, port_ranges, protocols,
      forward_address: d.forward_address.trim() || undefined,
      forward_port,
    },
  }
}

