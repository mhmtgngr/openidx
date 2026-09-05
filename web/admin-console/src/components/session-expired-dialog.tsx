import { useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from './ui/dialog'

interface SessionExpiredDialogProps {
  open: boolean
  onSignIn: () => void
}

/**
 * Non-dismissable modal shown when a request 401s mid-session. Gives the user one
 * clear path back (re-authenticate) instead of leaving them on masked-empty pages.
 */
export function SessionExpiredDialog({ open, onSignIn }: SessionExpiredDialogProps) {
  const { t } = useTranslation()
  if (!open) return null
  return (
    <Dialog open={open}>
      <DialogContent
        className="[&>button]:hidden"
        onPointerDownOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t('components.sessionExpired.title')}</DialogTitle>
          <DialogDescription>{t('components.sessionExpired.description')}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button onClick={onSignIn}>{t('components.sessionExpired.signIn')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
