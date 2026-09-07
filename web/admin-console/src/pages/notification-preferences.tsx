import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Send } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { Button } from '../components/ui/button'
import { QueryError } from '../components/query-error'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'

interface NotificationPreference {
  channel: string
  event_type: string
  enabled: boolean
}

/**
 * The switchable notification types come from the deployment, not from this
 * file.
 *
 * They used to be hard-coded here as seven names -- access_request,
 * security_alert, session_revoked, review_assigned, group_request,
 * password_expiry, mfa_change -- and this product has never sent a
 * notification of any of them, while the four types it does send appeared on no
 * switch. Every toggle on this page controlled nothing. The list is now
 * GET /notifications/preference-types, which serves
 * internal/notifications.TypeCatalogue, and a catalogue entry with no sender
 * fails the build.
 *
 * The wording still comes from the translation catalogues (the server's title
 * and description are the English fallback), so the page follows a language
 * switch as it did before.
 */
interface PreferenceType {
  type: string
  title: string
  description: string
  channels: string[]
}

const CHANNEL_ICONS: Record<string, typeof Bell> = {
  in_app: Bell,
  push: Send,
}

export function NotificationPreferencesPage() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const { toast } = useToast()
  const [prefs, setPrefs] = useState<Record<string, Record<string, boolean>>>({})
  const [dirty, setDirty] = useState(false)

  const { data, isError, error } = useQuery({
    queryKey: ['notification-preferences'],
    queryFn: () => api.get<{ preferences: NotificationPreference[] }>('/api/v1/identity/notifications/preferences'),
  })

  const {
    data: typesData,
    isError: typesError,
    error: typesErr,
  } = useQuery({
    queryKey: ['notification-preference-types'],
    queryFn: () => api.get<{ types: PreferenceType[] }>('/api/v1/identity/notifications/preference-types'),
  })
  const eventTypes: PreferenceType[] = typesData?.types ?? []
  const channels: string[] = Array.from(new Set(eventTypes.flatMap(e => e.channels)))

  useEffect(() => {
    if (data?.preferences) {
      const map: Record<string, Record<string, boolean>> = {}
      for (const p of data.preferences) {
        if (!map[p.event_type]) map[p.event_type] = {}
        map[p.event_type][p.channel] = p.enabled
      }
      setPrefs(map)
      setDirty(false)
    }
  }, [data])

  const isEnabled = (eventType: string, channel: string) => {
    return prefs[eventType]?.[channel] ?? true // default enabled
  }

  const toggle = (eventType: string, channel: string) => {
    setPrefs(prev => ({
      ...prev,
      [eventType]: {
        ...prev[eventType],
        [channel]: !isEnabled(eventType, channel),
      }
    }))
    setDirty(true)
  }

  const saveMutation = useMutation({
    mutationFn: (preferences: NotificationPreference[]) =>
      api.put('/api/v1/identity/notifications/preferences', { preferences }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-preferences'] })
      toast({ title: t('pages.notificationPreferences.saved') })
      setDirty(false)
    },
    onError: () =>
      toast({
        title: t('pages.notificationPreferences.saveFailed'),
        variant: 'destructive',
      }),
  })

  const handleSave = () => {
    const preferences: NotificationPreference[] = []
    for (const et of eventTypes) {
      for (const ch of et.channels) {
        preferences.push({
          channel: ch,
          event_type: et.type,
          enabled: isEnabled(et.type, ch),
        })
      }
    }
    saveMutation.mutate(preferences)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            {t('pages.notificationPreferences.title')}
          </h1>
          <p className="text-muted-foreground">
            {t('pages.notificationPreferences.subtitle')}
          </p>
        </div>
        <Button onClick={handleSave} disabled={!dirty || saveMutation.isPending}>
          {t('pages.notificationPreferences.save')}
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('pages.notificationPreferences.channelsTitle')}</CardTitle>
        </CardHeader>
        <CardContent>
          {isError ? (
            <QueryError error={error} resource={t('pages.notificationPreferences.resource')} />
          ) : typesError ? (
            // Without this the grid renders empty, which reads as "this
            // deployment sends nothing" -- the one thing a preferences page
            // must not say by accident.
            <QueryError error={typesErr} resource={t('pages.notificationPreferences.typesResource')} />
          ) : (
          <Table>
              <TableHeader>
                <TableRow className="border-b">
                  <TableHead className="text-left py-3 pr-4 font-medium text-sm">
                    {t('pages.notificationPreferences.colEvent')}
                  </TableHead>
                  {channels.map(ch => {
                    const Icon = CHANNEL_ICONS[ch] ?? Bell
                    return (
                      <TableHead key={ch} className="text-center py-3 px-4 font-medium text-sm">
                        <div className="flex items-center justify-center gap-1">
                          <Icon className="h-4 w-4" />
                          {t(`pages.notificationPreferences.channels.${ch}`, { defaultValue: ch })}
                        </div>
                      </TableHead>
                    )
                  })}
                </TableRow>
              </TableHeader>
              <TableBody>
                {eventTypes.map(et => (
                  <TableRow key={et.type} className="border-b last:border-0">
                    <TableCell className="py-4 pr-4">
                      <p className="font-medium text-sm">
                        {t(`pages.notificationPreferences.events.${et.type}`, { defaultValue: et.title })}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {t(`pages.notificationPreferences.eventHints.${et.type}`, { defaultValue: et.description })}
                      </p>
                    </TableCell>
                    {et.channels.map(ch => (
                      <TableCell key={ch} className="text-center py-4 px-4">
                        {/* On screen this toggle is identified by its row and
                            column. Read on its own it was one of a grid of
                            buttons with no name at all, so the label names
                            both axes and aria-checked carries the state. */}
                        <button
                          type="button"
                          role="switch"
                          aria-checked={isEnabled(et.type, ch)}
                          aria-label={t('pages.notificationPreferences.toggleLabel', {
                            channel: t(`pages.notificationPreferences.channels.${ch}`, { defaultValue: ch }),
                            event: t(`pages.notificationPreferences.events.${et.type}`, { defaultValue: et.title }),
                          })}
                          onClick={() => toggle(et.type, ch)}
                          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            isEnabled(et.type, ch) ? 'bg-primary' : 'bg-muted'
                          }`}
                        >
                          <span
                            aria-hidden="true"
                            className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                              isEnabled(et.type, ch) ? 'translate-x-6' : 'translate-x-1'
                            }`}
                          />
                        </button>
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
