import { Link, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ChevronRight } from 'lucide-react'
import { findNavPath } from '../config/navigation'

/** Routes that are their own root and get no breadcrumb trail. */
const ROOT_PATHS = new Set(['/', '/dashboard'])

/**
 * Derives a "<group> / <parent> / <page>" breadcrumb trail from the nav config
 * for the current route. Renders nothing on root routes (/ and /dashboard) or when the
 * path is not in the nav (e.g. detail pages), so pages don't need to wire it up.
 */
export function Breadcrumbs() {
  const { t } = useTranslation()
  const { pathname } = useLocation()
  if (ROOT_PATHS.has(pathname)) return null

  const match = findNavPath(pathname)
  if (!match) return null

  return (
    <nav aria-label={t('breadcrumb.ariaLabel')} className="flex items-center text-sm text-muted-foreground">
      {match.group.labelKey && (
        <>
          <span>{t(match.group.labelKey)}</span>
          <ChevronRight className="mx-1 h-4 w-4" aria-hidden="true" />
        </>
      )}
      {match.parent && (
        <>
          <Link to={match.parent.href} className="hover:text-foreground">
            {t(match.parent.nameKey)}
          </Link>
          <ChevronRight className="mx-1 h-4 w-4" aria-hidden="true" />
        </>
      )}
      <span className="font-medium text-foreground">{t(match.item.nameKey)}</span>
    </nav>
  )
}
