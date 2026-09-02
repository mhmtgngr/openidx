import {
  KeyRound, Lock, Monitor, Route, Server, Shield, Terminal, User, Video,
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
 * The launch chain for a session entry, as displayable steps. This is the
 * "how does clicking Connect actually work" story told with the entry's own
 * configuration: access gate → credential source → session broker → network
 * path → target. Pure function of the entry so it stays testable.
 */
export function connectionPathSteps(entry: PamEntry): ConnectionPathStep[] {
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
