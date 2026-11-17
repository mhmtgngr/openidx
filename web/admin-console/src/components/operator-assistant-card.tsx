import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Button } from './ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card'
import { api } from '../lib/api'

interface Reply {
  session_id?: string
  reply?: string
  assistant: boolean
  degraded?: boolean
}

interface AssistantSettings {
  provider?: string
  effective_mode?: string
  kill_switch?: boolean
}

/**
 * The operations assistant: a short conversation about the agent rollout and
 * about opening access, for operators. It can look things up and lay out a plan;
 * every change still waits for an administrator in the cards beside it, which
 * this refreshes after each answer. Shown only when the organization has chosen
 * a model and the assistant is on.
 */
export function OperatorAssistantCard() {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const settings = useQuery({
    queryKey: ['agentic-settings'],
    queryFn: () => api.get<AssistantSettings>('/api/v1/access/agentic/settings'),
  })
  const [text, setText] = useState('')
  const [sessionId, setSessionId] = useState<string | undefined>()
  const [turns, setTurns] = useState<{ who: 'you' | 'assistant'; text: string }[]>([])
  const [note, setNote] = useState<string | null>(null)

  const ask = useMutation({
    mutationFn: (message: string) =>
      api.post<Reply>('/api/v1/access/assist/operator/messages', {
        message, session_id: sessionId, lang: i18n.language?.startsWith('tr') ? 'tr' : 'en',
      }),
    onSuccess: (r) => {
      setSessionId(r.session_id ?? sessionId)
      if (r.assistant && r.reply) {
        setTurns((cur) => [...cur, { who: 'assistant', text: r.reply! }])
        setNote(null)
      } else {
        setNote(t('operatorAssistant.unavailable'))
      }
      // The assistant may have laid out a plan or looked at the rollout.
      queryClient.invalidateQueries({ queryKey: ['access-plans'] })
      queryClient.invalidateQueries({ queryKey: ['agent-rollout'] })
    },
    onError: (e) => setNote(
      (e as { response?: { status?: number } })?.response?.status === 429
        ? t('operatorAssistant.tooMany')
        : t('operatorAssistant.failed'),
    ),
  })

  const s = settings.data
  if (!s || !s.provider || s.provider === 'none' || s.effective_mode === 'off' || s.kill_switch) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('operatorAssistant.title')}</CardTitle>
        <CardDescription>{t('operatorAssistant.description')}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {turns.length > 0 && (
          <ul className="space-y-2">
            {turns.map((turn, i) => (
              <li key={i}>
                <span className="font-medium">{t(`operatorAssistant.${turn.who}`)}: </span>
                <span className="whitespace-pre-wrap">{turn.text}</span>
              </li>
            ))}
          </ul>
        )}
        {ask.isPending && <p className="text-xs text-muted-foreground">{t('operatorAssistant.thinking')}</p>}
        {note && <p role="alert" className="text-muted-foreground">{note}</p>}
        <form
          className="flex gap-2"
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
          <input
            aria-label={t('operatorAssistant.title')}
            value={text}
            maxLength={2000}
            onChange={(e) => setText(e.target.value)}
            placeholder={t('operatorAssistant.placeholder')}
            className="h-9 flex-1 rounded-md border border-input bg-background px-3 text-sm"
          />
          <Button type="submit" size="sm" disabled={ask.isPending || !text.trim()}>{t('operatorAssistant.send')}</Button>
        </form>
      </CardContent>
    </Card>
  )
}
