import { AlertTriangle, ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '../lib/utils'

/** Extract the HTTP status from a rejected api/axios error, if present. */
export function getErrorStatus(error: unknown): number | undefined {
  return (error as { response?: { status?: number } } | null)?.response?.status
}

interface QueryErrorProps {
  /** The error object from a react-query `useQuery`/`useMutation`. */
  error: unknown
  /**
   * Human-readable name of what failed to load, e.g. "audit logs". Pass it
   * already localized (a t() result) — it is interpolated into the sentence
   * as-is.
   */
  resource?: string
  className?: string
}

/**
 * Consistent error state for failed data fetches. Critically, it distinguishes
 * a 401/403 (an authorization failure) from a generic load error, so a
 * permission denial is never silently rendered as a normal "no data" empty
 * state — the pattern that hid the My Profile → Sessions 403.
 */
export function QueryError({ error, resource, className }: QueryErrorProps) {
  const { t } = useTranslation()
  const status = getErrorStatus(error)
  const isAuth = status === 401 || status === 403

  const what = resource ?? t('queryError.defaultResource')
  const message = isAuth
    ? status === 401
      ? t('queryError.sessionExpired')
      : t('queryError.noPermission', { resource: what })
    : t('queryError.loadFailed', { resource: what })

  const Icon = isAuth ? ShieldAlert : AlertTriangle

  return (
    <div className={cn('py-12 text-center', className)}>
      <Icon className="mx-auto mb-3 h-10 w-10 text-red-500" />
      <p className="text-sm font-medium text-red-600">{message}</p>
    </div>
  )
}
