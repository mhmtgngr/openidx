import { useTranslation } from 'react-i18next'
import { ShieldAlert } from 'lucide-react'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Button } from './ui/button'
import { statusLines, recordNoticeAck, PAM_GUIDE_URL, type PamRuleFlags } from '../lib/pam-clarity'

export interface NoticeEntry extends PamRuleFlags { id: string; name: string }

interface Props {
  entry: NoticeEntry | null
  onContinue: () => void
  onCancel: () => void
}

/** PamSessionNotice: the consent-style "before you connect" dialog. */
export function PamSessionNotice({ entry, onContinue, onCancel }: Props) {
  const { t } = useTranslation()
  const lines = entry ? statusLines(entry).filter((l) => ['recorded', 'watermark', 'moderated'].includes(l.id)) : []
  return (
    <Dialog open={!!entry} onOpenChange={(o) => { if (!o) onCancel() }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-amber-600" />
            {t('pamClarity.notice.title', { name: entry?.name ?? '' })}
          </DialogTitle>
          <DialogDescription>{t('pamClarity.notice.intro')}</DialogDescription>
        </DialogHeader>
        <ul className="list-disc pl-5 space-y-1 text-sm" data-testid="pam-notice-lines">
          {lines.map((l) => <li key={l.id}>{t(l.key)}</li>)}
        </ul>
        <div className="space-y-1 text-sm text-muted-foreground">
          <p>{t('pamClarity.notice.whoCanSee')}</p>
          <p>{t('pamClarity.notice.retention')}</p>
          <p>{t('pamClarity.notice.rights')}</p>
          <a href={PAM_GUIDE_URL} target="_blank" rel="noreferrer" className="text-primary hover:underline">
            {t('pamClarity.howItWorks')}
          </a>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel}>{t('common.cancel')}</Button>
          <Button onClick={() => { if (entry) recordNoticeAck(entry.id, entry); onContinue() }}>
            {t('pamClarity.notice.continue')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
