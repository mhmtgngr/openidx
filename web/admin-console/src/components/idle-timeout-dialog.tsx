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
          <DialogTitle>Session Expiring Soon</DialogTitle>
          <DialogDescription>
            Your session will expire in{' '}
            <span className="font-mono font-bold text-foreground">
              {timeDisplay}
            </span>{' '}
            due to inactivity.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="flex gap-2 sm:justify-between">
          <Button variant="outline" onClick={onSignOut}>
            Sign Out
          </Button>
          <Button onClick={onKeepAlive}>Keep Me Signed In</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
