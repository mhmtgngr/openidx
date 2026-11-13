// Plain-language explanations of privileged access rules, shared by the end-user
// My privileged access page and the operator PAM connections page. Pure: every
// function returns i18n keys (and interpolation values), never rendered text.

export const PAM_GUIDE_URL = 'https://mhmtgngr.github.io/openidx/guide/privileged-access/'

/** The entry flags that change what happens to a user during a session. */
export interface PamRuleFlags {
  record_session?: boolean
  require_approval?: boolean
  require_moderator?: boolean
  exclusive_checkout?: boolean
  dual_control_required?: boolean
  break_glass_enabled?: boolean
  allow_reveal?: boolean
  has_secret?: boolean
  watermark?: boolean | { text?: string } | null
  reach_mode?: string
  ziti_enabled?: boolean
}

export interface ClarityLine {
  /** Stable id, useful as a React key and a chip id. */
  id: string
  /** Short chip label key. */
  chipKey: string
  /** Full sentence key. */
  key: string
}

const K = 'pamClarity.status'

const hasWatermark = (w: PamRuleFlags['watermark']) =>
  typeof w === 'boolean' ? w : !!(w && (typeof w !== 'object' || w.text !== ''))

/** statusLines maps the entry's flags to sentences, in a fixed order. */
export function statusLines(entry: PamRuleFlags): ClarityLine[] {
  const out: ClarityLine[] = []
  const add = (id: string) => out.push({ id, chipKey: `${K}.${id}.chip`, key: `${K}.${id}.text` })
  if (entry.record_session) add('recorded')
  if (hasWatermark(entry.watermark)) add('watermark')
  if (entry.require_moderator) add('moderated')
  if (entry.require_approval) add('approval')
  if (entry.dual_control_required) add('dualControl')
  if (entry.exclusive_checkout) add('exclusive')
  if (entry.break_glass_enabled) add('breakGlass')
  if (entry.allow_reveal && entry.has_secret !== false) add('reveal')
  if (entry.reach_mode === 'ziti' || entry.ziti_enabled) add('ziti')
  return out
}

/** The flags that decide whether the session notice must be acknowledged. */
export function needsNotice(entry: PamRuleFlags): boolean {
  return !!entry.record_session || !!entry.require_moderator || hasWatermark(entry.watermark)
}

/** A stable fingerprint of the rules the notice describes. */
export function rulesHash(entry: PamRuleFlags): string {
  return statusLines(entry).map((l) => l.id).join('|')
}

export interface Refusal {
  key: string
  values?: Record<string, string>
}

/**
 * refusalMessage turns a refused connect or reveal into a sentence that tells
 * the user what to do next. `body` is the JSON the server answered with.
 */
export function refusalMessage(status: number | undefined, body?: Record<string, unknown> | null): Refusal {
  const R = 'pamClarity.refusal'
  const b = body || {}
  const code = typeof b.code === 'string' ? b.code : ''
  const str = (k: string) => (typeof b[k] === 'string' ? (b[k] as string) : '')

  switch (code) {
    case 'device_trust_required': return { key: `${R}.deviceTrust` }
    case 'authentication_required': return { key: `${R}.signIn` }
    case 'approval_required': return { key: `${R}.approval` }
    case 'launch_request_expired': return { key: `${R}.requestExpired` }
    case 'credential_unresolved':
    case 'credential_unavailable': return { key: `${R}.credential` }
    case 'external_launch_needs_sponsor': return { key: `${R}.externalSponsor` }
    case 'external_recording_unavailable': return { key: `${R}.externalRecording` }
    case 'external_broker_identity_required': return { key: `${R}.externalIdentity` }
    case 'external_not_activated':
    case 'external_account_not_live': return { key: `${R}.externalNotLive` }
    case 'external_not_permitted':
    case 'external_role_cap':
    case 'external_group_not_allowed': return { key: `${R}.externalNotPermitted` }
  }
  if (code.startsWith('external_')) return { key: `${R}.externalOther` }
  if (code.startsWith('ztna_') || code.includes('ziti')) return { key: `${R}.ztna` }

  if (status === 202 || str('status') === 'awaiting_authorization') return { key: `${R}.dualControl` }
  if (str('status') === 'awaiting_moderator' || b.awaiting_moderator === true) return { key: `${R}.moderator` }
  if (status === 409 && 'held_by' in b) {
    const holder = str('held_by')
    const until = str('held_until') || str('expires_at')
    if (holder && until) return { key: `${R}.exclusiveHolderUntil`, values: { holder, until } }
    if (holder) return { key: `${R}.exclusiveHolder`, values: { holder } }
    return { key: `${R}.exclusive` }
  }
  if (b.approval_required === true || /requires approval/i.test(str('error'))) return { key: `${R}.approval` }
  if (status === 401) return { key: `${R}.signIn` }
  if (status === 403) return { key: `${R}.notPermitted` }
  if (status === 404) return { key: `${R}.notFound` }
  return { key: `${R}.generic` }
}

export const NOTICE_TTL_MS = 30 * 24 * 60 * 60 * 1000
const storageKey = (entryId: string) => `openidx.pamNotice.${entryId}`

interface StoredAck { ack_at: number; rules_hash: string }

/**
 * shouldShowNotice: the entry records, is moderated or watermarks, and the user
 * has not acknowledged this exact rule set within the last 30 days.
 */
export function shouldShowNotice(entryId: string, flags: PamRuleFlags, now: number = Date.now()): boolean {
  if (!needsNotice(flags)) return false
  try {
    const raw = localStorage.getItem(storageKey(entryId))
    if (!raw) return true
    const ack = JSON.parse(raw) as StoredAck
    if (typeof ack.ack_at !== 'number' || ack.rules_hash !== rulesHash(flags)) return true
    return now - ack.ack_at >= NOTICE_TTL_MS
  } catch {
    return true
  }
}

export function recordNoticeAck(entryId: string, flags: PamRuleFlags, now: number = Date.now()) {
  try {
    const ack: StoredAck = { ack_at: now, rules_hash: rulesHash(flags) }
    localStorage.setItem(storageKey(entryId), JSON.stringify(ack))
  } catch {
    // Storage unavailable: the notice simply shows again next time.
  }
}

