import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ShieldAlert } from 'lucide-react'
import { useAuth } from '../lib/auth'
import { useEnforcementPosture } from '../lib/enforcement'

/**
 * One line at the top of the dashboard while any control is open: how many,
 * how long the window has left, and the link to the page that says what each
 * would have refused. Nothing is rendered for a fully enforcing install or
 * for a reader who could not act on it.
 */
export function EnforcementBanner() {
  const { t } = useTranslation()
  const { hasRole } = useAuth()
  const isAdmin = hasRole('admin')
  const { data } = useEnforcementPosture(isAdmin)
  if (!isAdmin || !data || data.fully_enforcing) return null

  const open = data.gates.filter((g) => !g.enforcing).length
  const wouldDeny = data.gates.reduce((n, g) => n + (g.would_deny_7d || 0), 0)
  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-100"
    >
      <ShieldAlert className="h-5 w-5 shrink-0" />
      <span className="font-medium">{t('pages.enforcement.banner.title', { count: open })}</span>
      <span>
        {data.observe_days_left !== undefined && data.observe_until
          ? t('pages.enforcement.banner.window', { days: data.observe_days_left, until: data.observe_until })
          : t('pages.enforcement.banner.noWindow')}
        {' · '}
        {t('pages.enforcement.banner.wouldDeny', { count: wouldDeny })}
      </span>
      <Link to="/enforcement" className="ml-auto font-medium underline underline-offset-2">
        {t('pages.enforcement.banner.link')}
      </Link>
    </div>
  )
}
