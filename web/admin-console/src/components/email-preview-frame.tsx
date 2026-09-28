import { useTranslation } from 'react-i18next'

/**
 * An email template's HTML as its recipients will see it, kept away from the
 * console. The HTML is one administrator's, and other administrators, platform
 * admins among them, open it here. Placed in the page, it would run with the
 * console's origin, where their access and refresh tokens are kept. A srcdoc
 * frame whose sandbox grants nothing runs no script and has an opaque origin;
 * mail clients run no script either, so the email still looks as it will.
 *
 * The frame is white in either theme, as a mail client's canvas is: an email
 * that sets no colours is dark text on white, and the console's dark
 * background would leave it unreadable.
 */
export function EmailPreviewFrame({ html }: { html: string }) {
  const { t } = useTranslation()
  return (
    <iframe
      title={t('pages.emailTemplates.editor.previewFrame')}
      sandbox=""
      srcDoc={html}
      className="mt-1 h-[32rem] w-full rounded border bg-white"
    />
  )
}
