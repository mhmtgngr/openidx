import { Languages, Check } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { supportedLanguages } from '@/i18n'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

// Picks the UI language. The choice persists in localStorage ('openidx.lang'
// via the i18n detector config) and applies immediately — no reload.
export function LanguageSwitcher() {
  const { i18n, t } = useTranslation()
  // resolvedLanguage collapses regional variants (en-US → en).
  const current = i18n.resolvedLanguage ?? i18n.language

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" aria-label={t('switcher.label')}>
          <Languages className="h-4 w-4" />
          <span className="ml-1.5 uppercase">{current}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {supportedLanguages.map((lang) => (
          <DropdownMenuItem
            key={lang.code}
            onClick={() => void i18n.changeLanguage(lang.code)}
          >
            <span className="flex-1">{lang.label}</span>
            {current === lang.code && <Check className="ml-2 h-4 w-4" />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
