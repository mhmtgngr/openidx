import { useTranslation } from 'react-i18next'
import { Sun, Moon, Monitor } from 'lucide-react'
import { useAppStore } from '../lib/store'
import { Button } from './ui/button'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from './ui/dropdown-menu'

type Theme = 'light' | 'dark' | 'system'

// Module-level, so the label has to be a KEY: an English string here would be
// frozen at import time and would not follow a language switch.
const OPTIONS: { value: Theme; labelKey: string; icon: typeof Sun }[] = [
  { value: 'light', labelKey: 'components.theme.light', icon: Sun },
  { value: 'dark', labelKey: 'components.theme.dark', icon: Moon },
  { value: 'system', labelKey: 'components.theme.system', icon: Monitor },
]

/**
 * Header control that switches between light, dark and system themes. Reads and
 * writes the shared app store; App.tsx applies the resulting `.dark` root class.
 */
export function ThemeToggle() {
  const { t } = useTranslation()
  const { theme, setTheme } = useAppStore()
  const active = OPTIONS.find((o) => o.value === theme) ?? OPTIONS[2]
  const ActiveIcon = active.icon

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={t('components.theme.toggle')}>
          <ActiveIcon className="h-5 w-5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {OPTIONS.map(({ value, labelKey, icon: Icon }) => (
          <DropdownMenuItem key={value} onSelect={() => setTheme(value)}>
            <Icon className="h-4 w-4" />
            {t(labelKey)}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
