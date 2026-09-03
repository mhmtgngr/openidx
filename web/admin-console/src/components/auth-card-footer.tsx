import { useTranslation } from 'react-i18next'

/**
 * Footer shared by the login card and the two password-recovery cards: real
 * destinations only — the published docs site and the security policy.
 *
 * The Privacy / Terms / Help trio these cards used to render was link-styled
 * text with no destinations at all, naming pages this project does not have.
 * The login card was fixed first; sharing one component is what keeps the
 * other two from drifting back.
 */
export function AuthCardFooter() {
  const { t } = useTranslation()
  return (
    <div className="px-6 py-4 bg-muted border-t border-border rounded-b-lg">
      <div className="flex items-center justify-center gap-4 text-xs text-muted-foreground">
        <a
          href="https://mhmtgngr.github.io/openidx"
          target="_blank"
          rel="noreferrer"
          className="hover:text-foreground"
        >
          {t('landing.nav.documentation')}
        </a>
        <span>•</span>
        <a
          href="https://github.com/mhmtgngr/openidx/blob/main/SECURITY.md"
          target="_blank"
          rel="noreferrer"
          className="hover:text-foreground"
        >
          {t('login.footer.security')}
        </a>
      </div>
    </div>
  )
}

/** The "Powered by OpenIDX" line under an auth card. */
export function PoweredBy() {
  const { t } = useTranslation()
  return (
    <p className="text-sm text-muted-foreground">
      {t('login.footer.poweredBy')} <span className="font-semibold text-foreground">OpenIDX</span>
    </p>
  )
}
