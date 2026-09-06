import { Trans, useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog'

interface IdleTimeoutDialogProps {
  open: boolean
  remainingTime: number
  onKeepAlive: () => void
  onSignOut: () => void
}

export function IdleTimeoutDialog({
  open,
  remainingTime,
  onKeepAlive,
  onSignOut,
}: IdleTimeoutDialogProps) {
  const { t } = useTranslation()
  const minutes = Math.floor(remainingTime / 60)
  const seconds = remainingTime % 60
  const timeDisplay = `${minutes}:${seconds.toString().padStart(2, '0')}`

  return (
    <Dialog open={open}>
      <DialogContent
        className="sm:max-w-md"
        onPointerDownOutside={(e) => e.preventDefault()}
        onEscapeKeyDown={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t('components.idleTimeout.title')}</DialogTitle>
          <DialogDescription>
            {/* The countdown is inside the sentence, so the whole line is one
                key: a locale that puts the time elsewhere can move it, and the
                monospace styling travels with it. */}
            <Trans
              i18nKey="components.idleTimeout.description"
              values={{ time: timeDisplay }}
              components={{ clock: <span className="font-mono font-bold text-foreground" /> }}
            />
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="flex gap-2 sm:justify-between">
          <Button variant="outline" onClick={onSignOut}>
            {t('components.idleTimeout.signOut')}
          </Button>
          <Button onClick={onKeepAlive}>{t('components.idleTimeout.keepAlive')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
