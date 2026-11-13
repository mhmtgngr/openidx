import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import en from '../i18n/locales/en'
import tr from '../i18n/locales/tr'
import {
  statusLines, refusalMessage, needsNotice, shouldShowNotice, recordNoticeAck, NOTICE_TTL_MS,
} from './pam-clarity'

const get = (o: unknown, path: string) =>
  path.split('.').reduce<unknown>((a, k) => (a as Record<string, unknown> | undefined)?.[k], o)

const allFlags = {
  record_session: true, require_approval: true, require_moderator: true, exclusive_checkout: true,
  dual_control_required: true, break_glass_enabled: true, allow_reveal: true, has_secret: true,
  watermark: { text: 'alice' }, reach_mode: 'ziti',
}

describe('statusLines', () => {
  it('maps every flag to a sentence present in en and tr', () => {
    const lines = statusLines(allFlags)
    expect(lines.map((l) => l.id)).toEqual([
      'recorded', 'watermark', 'moderated', 'approval', 'dualControl', 'exclusive', 'breakGlass', 'reveal', 'ziti',
    ])
    for (const l of lines) {
      for (const cat of [en, tr]) {
        expect(typeof get(cat, l.key)).toBe('string')
        expect(typeof get(cat, l.chipKey)).toBe('string')
      }
      expect(get(tr, l.key)).not.toEqual(get(en, l.key))
    }
  })
  it('is empty for a plain entry', () => {
    expect(statusLines({})).toEqual([])
    expect(needsNotice({ require_approval: true })).toBe(false)
    expect(needsNotice({ watermark: true })).toBe(true)
  })
})

describe('refusalMessage', () => {
  const cases: [number, Record<string, unknown>, string][] = [
    [409, { held_by: 'bob', held_until: '12:00' }, 'exclusiveHolderUntil'],
    [409, { held_by: 'bob' }, 'exclusiveHolder'],
    [202, { status: 'awaiting_authorization' }, 'dualControl'],
    [403, { code: 'device_trust_required' }, 'deviceTrust'],
    [403, { error: 'session requires approval', approval_required: true }, 'approval'],
    [403, { code: 'external_launch_needs_sponsor' }, 'externalSponsor'],
    [403, { code: 'external_recording_unavailable' }, 'externalRecording'],
    [403, { code: 'external_broker_identity_required' }, 'externalIdentity'],
    [403, { code: 'external_email_domain' }, 'externalOther'],
    [403, { code: 'ztna_required_direct_reach' }, 'ztna'],
    [409, { code: 'launch_request_expired' }, 'requestExpired'],
    [403, { awaiting_moderator: true }, 'moderator'],
    [500, {}, 'generic'],
  ]
  it.each(cases)('%i %j -> %s', (status, body, id) => {
    const m = refusalMessage(status, body)
    expect(m.key).toBe(`pamClarity.refusal.${id}`)
    expect(typeof get(en, m.key)).toBe('string')
    expect(typeof get(tr, m.key)).toBe('string')
  })
  it('interpolates the holder', () => {
    expect(refusalMessage(409, { held_by: 'bob', held_until: 'noon' }).values).toEqual({ holder: 'bob', until: 'noon' })
  })
})

describe('session notice acknowledgement', () => {
  beforeEach(() => { localStorage.clear(); vi.useFakeTimers(); vi.setSystemTime(new Date('2026-01-01T00:00:00Z')) })
  afterEach(() => vi.useRealTimers())
  const rec = { record_session: true }

  it('never shows for entries without monitoring', () => {
    expect(shouldShowNotice('e1', { require_approval: true })).toBe(false)
  })
  it('shows until acknowledged, then hides for 30 days', () => {
    expect(shouldShowNotice('e1', rec)).toBe(true)
    recordNoticeAck('e1', rec)
    expect(shouldShowNotice('e1', rec)).toBe(false)
    vi.advanceTimersByTime(NOTICE_TTL_MS - 1000)
    expect(shouldShowNotice('e1', rec)).toBe(false)
    vi.advanceTimersByTime(2000)
    expect(shouldShowNotice('e1', rec)).toBe(true)
  })
  it('re-shows when the rule set changes', () => {
    recordNoticeAck('e1', rec)
    expect(shouldShowNotice('e1', { ...rec, require_moderator: true })).toBe(true)
    expect(shouldShowNotice('e2', rec)).toBe(true)
  })
})
