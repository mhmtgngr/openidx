import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { CheckCircle2, CircleHelp, TriangleAlert } from 'lucide-react'
import { Button } from './ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { LoadingSpinner } from './ui/loading-spinner'
import { api } from '../lib/api'

interface Cause {
  code: string
  source: 'device' | 'server'
  fixes: { action: string; tier: string }[]
}

export interface MyDiagnosis {
  agent_id?: string
  verdict: { healthy: boolean; causes: Cause[]; bundle_stale?: boolean }
  bundle_at?: string
  bundle_requested?: boolean
  assistant_available?: boolean
  generated_at: string
}

/** How long a device gets to answer a "diagnose" command before the card asks again. */
export const RECHECK_AFTER_MS = 40_000

/**
 * "Why can't I connect?" for one of the signed-in person's own devices: the
 * newest-reporting one, or `agentId`. The server decides the causes by rule;
 * this only words them. A cause this build has no words for falls back to
 * UNKNOWN rather than showing a raw code.
 */
interface AssistReply {
  session_id?: string
  reply?: string
  assistant: boolean
  degraded?: boolean
}

/** One question to the assistant. The verdict above never depends on the answer. */
function AssistantChat({ agentId }: { agentId?: string }) {
  const { t, i18n } = useTranslation()
  const [text, setText] = useState('')
  const [sessionId, setSessionId] = useState<string | undefined>()
  const [turns, setTurns] = useState<{ who: 'you' | 'assistant'; text: string }[]>([])
  const [note, setNote] = useState<string | null>(null)
  const ask = useMutation({
    mutationFn: (message: string) =>
      api.post<AssistReply>('/api/v1/access/my/assist/messages', {
        message, session_id: sessionId, agent_id: agentId, lang: i18n.language?.startsWith('tr') ? 'tr' : 'en',
      }),
    onSuccess: (r) => {
      setSessionId(r.session_id ?? sessionId)
      if (r.assistant && r.reply) {
        setTurns((cur) => [...cur, { who: 'assistant', text: r.reply! }])
        setNote(null)
      } else {
        setNote(t('diagnose.assist.unavailable'))
      }
    },
    onError: (e) => setNote(
      (e as { response?: { status?: number } })?.response?.status === 429 ? t('diagnose.assist.tooMany') : t('diagnose.assist.failed'),
    ),
  })
  return (
    <form
      className="space-y-2 border-t pt-3"
      onSubmit={(e) => {
        e.preventDefault()
        const q = text.trim()
        if (!q || ask.isPending) return
        setTurns((cur) => [...cur, { who: 'you', text: q }])
        setText('')
        setNote(null)
        ask.mutate(q)
      }}
    >
      <p className="text-sm font-medium">{t('diagnose.assist.title')}</p>
      {turns.length > 0 && (
        <ul className="space-y-2 text-sm">
          {turns.map((turn, i) => (
            <li key={i}>
              <span className="font-medium">{t(`diagnose.assist.${turn.who}`)}: </span>
              <span className="whitespace-pre-wrap">{turn.text}</span>
            </li>
          ))}
        </ul>
      )}
      {ask.isPending && <p className="text-xs text-muted-foreground">{t('diagnose.assist.thinking')}</p>}
      {note && <p role="alert" className="text-sm text-muted-foreground">{note}</p>}
      <div className="flex gap-2">
        <input
          aria-label={t('diagnose.assist.title')}
          value={text}
          maxLength={2000}
          onChange={(e) => setText(e.target.value)}
          placeholder={t('diagnose.assist.placeholder')}
          className="h-9 flex-1 rounded-md border border-input bg-background px-3 text-sm"
        />
        <Button type="submit" size="sm" disabled={ask.isPending || !text.trim()}>{t('diagnose.assist.send')}</Button>
      </div>
    </form>
  )
}

export function WhyCantIConnect({ agentId }: { agentId?: string }) {
  const { t, i18n } = useTranslation()
  const diagnose = useMutation({
    mutationFn: () =>
      api.post<MyDiagnosis>('/api/v1/access/my/diagnose', agentId ? { agent_id: agentId } : {}),
  })
  const result = diagnose.data

  // When the server has just asked the device to look at itself, ask again
  // once the device has had time to answer. Once only: a device that does not
  // answer must not turn this card into a poll.
  const [followedUp, setFollowedUp] = useState(false)
  const { mutate } = diagnose
  const asking = Boolean(result?.bundle_requested) && !followedUp
  useEffect(() => {
    if (!asking) return
    const timer = setTimeout(() => {
      setFollowedUp(true)
      mutate()
    }, RECHECK_AFTER_MS)
    return () => clearTimeout(timer)
  }, [asking, mutate])
  const words = (code: string, part: 'title' | 'action') => {
    const key = `diagnose.cause.${code}.${part}`
    return i18n.exists(key) ? t(key) : t(`diagnose.cause.UNKNOWN.${part}`)
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          <CircleHelp className="h-4 w-4 text-muted-foreground" />
          {t('diagnose.title')}
        </CardTitle>
        <CardDescription>{t('diagnose.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            setFollowedUp(false)
            diagnose.mutate()
          }}
          disabled={diagnose.isPending}
        >
          {diagnose.isPending ? <LoadingSpinner size="sm" /> : null}
          <span className={diagnose.isPending ? 'ml-2' : ''}>
            {diagnose.isPending ? t('diagnose.checking') : result ? t('diagnose.again') : t('diagnose.button')}
          </span>
        </Button>

        {diagnose.isError && (
          <p role="alert" className="text-sm text-destructive">{t('diagnose.failed')}</p>
        )}

        {result && !diagnose.isPending && result.verdict.healthy && (
          <div role="status" className="flex items-start gap-2 text-sm">
            <CheckCircle2 className="h-4 w-4 mt-0.5 text-green-600 shrink-0" />
            <div>
              <p className="font-medium">{t('diagnose.healthy')}</p>
              <p className="text-muted-foreground">{t('diagnose.healthyHint')}</p>
            </div>
          </div>
        )}

        {result && !diagnose.isPending && !result.verdict.healthy && (
          <ol role="status" className="space-y-3">
            {result.verdict.causes.map((cause, i) => (
              <li key={cause.code} className="flex items-start gap-2 text-sm">
                <TriangleAlert
                  className={`h-4 w-4 mt-0.5 shrink-0 ${i === 0 ? 'text-destructive' : 'text-muted-foreground'}`}
                />
                <div>
                  <p className="font-medium">{words(cause.code, 'title')}</p>
                  <p className="text-muted-foreground">{words(cause.code, 'action')}</p>
                </div>
              </li>
            ))}
          </ol>
        )}

        {result?.assistant_available && <AssistantChat agentId={result.agent_id ?? agentId} />}

        {result && !diagnose.isPending && asking && (
          <p className="text-xs text-muted-foreground">{t('diagnose.asking')}</p>
        )}
        {result && !diagnose.isPending && !asking && !result.bundle_at && result.agent_id && (
          <p className="text-xs text-muted-foreground">{t('diagnose.noBundleHint')}</p>
        )}
      </CardContent>
    </Card>
  )
}
