import {
  KeyRound, Lock, Monitor, Route, Server, Shield, ShieldOff, Terminal, User, Video,
  type LucideIcon,
} from 'lucide-react'

import i18n from '../i18n'
import type { PamEntry } from './api'

export interface ConnectionPathStep {
  icon: LucideIcon
  title: string
  desc: string
}

// Resolved through the i18n singleton rather than a hook: this is a pure
// function called from render, not a component.
const t = (key: string, vars?: Record<string, unknown>) => i18n.t(`pam.path.${key}`, vars ?? {})

/**
 * Why this entry cannot be launched under the ZTNA gate, or null when it can.
 *
 * `PAM_REQUIRE_ZTNA=enforce` refuses a launch whose target hop is not the
 * overlay, and refuses a website entry outright — it returns a URL and brokers
 * nothing, so no part of it travels the overlay. The mode comes from
 * `/pam/broker/status`; when it is undefined (an older service, or the probe
 * has not resolved yet) nothing is refused, because guessing "enforce" would
 * grey out a button that works.
 *
 * `observe` refuses nothing on the server, so it must refuse nothing here
 * either. A console that greys out what the server would still allow is the
 * same lie as one that offers what the server will refuse.
 */
export function ztnaRefusal(entry: PamEntry, requireZTNA?: string): string | null {
  if (requireZTNA !== 'enforce') return null
  if (entry.kind !== 'session') return t('ztnaRefused.website')
  if (!entry.ziti_enabled) return t('ztnaRefused.direct')
  return null
}

/**
 * The launch chain for a session entry, as displayable steps. This is the
 * "how does clicking Connect actually work" story told with the entry's own
 * configuration: access gate → credential source → session broker → network
 * path → target. Pure function of the entry so it stays testable.
 *
 * requireZTNA is the gate's mode. It matters here because the network step used
 * to draw a direct hop as a working route in every case, and under enforcement
 * that route does not exist: the launch is refused before a credential is even
 * resolved. Drawing it as a path anyway would describe a session nobody can
 * open.
 */
export function connectionPathSteps(entry: PamEntry, requireZTNA?: string): ConnectionPathStep[] {
  const remoteApp = typeof entry.settings['remote-app'] === 'string'
    ? String(entry.settings['remote-app']).replace(/^\|\|/, '')
    : ''
  const proto = entry.entry_type.toUpperCase()
  const steps: ConnectionPathStep[] = [
    entry.require_approval
      ? { icon: Lock, title: t('approvalGate.title'), desc: t('approvalGate.desc') }
      : { icon: User, title: t('youConnect.title'), desc: t('youConnect.desc') },
    entry.credential_entry_name
      ? {
          icon: KeyRound,
          title: t('linkedCredential.title', { name: entry.credential_entry_name }),
          desc: t('linkedCredential.desc'),
        }
      : entry.has_secret
        ? { icon: KeyRound, title: t('vaultedSecret.title'), desc: t('vaultedSecret.desc') }
        : { icon: KeyRound, title: t('noCredential.title'), desc: t('noCredential.desc') },
    entry.renderer === 'wasm-ssh'
      ? { icon: Terminal, title: t('browserTerminal.title'), desc: t('browserTerminal.desc') }
      : remoteApp
        ? {
            icon: Monitor,
            title: t('remoteApp.title', { app: remoteApp }),
            desc: t('remoteApp.desc', { app: remoteApp, proto }),
          }
        : {
            icon: Monitor,
            title: t('guacSession.title', { proto }),
            desc: t('guacSession.desc'),
          },
  ]
  if (entry.record_session) {
    steps.push({ icon: Video, title: t('recording.title'), desc: t('recording.desc') })
  }
  steps.push(
    entry.ziti_enabled
      ? { icon: Shield, title: t('ziti.title'), desc: t('ziti.desc') }
      : requireZTNA === 'enforce'
        ? { icon: ShieldOff, title: t('directRefused.title'), desc: t('directRefused.desc') }
        : { icon: Route, title: t('direct.title'), desc: t('direct.desc') },
    {
      icon: Server,
      title: entry.hostname
        ? `${entry.hostname}${entry.port ? `:${entry.port}` : ''}`
        : t('target.title'),
      desc: entry.username
        ? entry.domain
          ? t('target.signedInAsDomain', { user: entry.username, domain: entry.domain })
          : t('target.signedInAs', { user: entry.username })
        : t('target.desc'),
    },
  )
  return steps
}
