import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Mail } from 'lucide-react'
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
 * The notification service's own event and channel keys. The label and the
 * line under it are resolved at render, so they follow a language switch
 * instead of freezing English at import time.
 */
const EVENT_TYPES = [
  'access_request',
  'security_alert',
  'session_revoked',
  'review_assigned',
  'group_request',
  'password_expiry',
  'mfa_change',
] as const

const CHANNELS = [
  { key: 'in_app', icon: Bell },
  { key: 'email', icon: Mail },
] as const

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
    for (const et of EVENT_TYPES) {
      for (const ch of CHANNELS) {
        preferences.push({
          channel: ch.key,
          event_type: et,
          enabled: isEnabled(et, ch.key),
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
          ) : (
          <Table>
              <TableHeader>
                <TableRow className="border-b">
                  <TableHead className="text-left py-3 pr-4 font-medium text-sm">
                    {t('pages.notificationPreferences.colEvent')}
                  </TableHead>
                  {CHANNELS.map(ch => (
                    <TableHead key={ch.key} className="text-center py-3 px-4 font-medium text-sm">
                      <div className="flex items-center justify-center gap-1">
                        <ch.icon className="h-4 w-4" />
                        {t(`pages.notificationPreferences.channels.${ch.key}`)}
                      </div>
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {EVENT_TYPES.map(et => (
                  <TableRow key={et} className="border-b last:border-0">
                    <TableCell className="py-4 pr-4">
                      <p className="font-medium text-sm">
                        {t(`pages.notificationPreferences.events.${et}`)}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {t(`pages.notificationPreferences.eventHints.${et}`)}
                      </p>
                    </TableCell>
                    {CHANNELS.map(ch => (
                      <TableCell key={ch.key} className="text-center py-4 px-4">
                        {/* On screen this toggle is identified by its row and
                            column. Read on its own it was one of fourteen
                            buttons with no name at all, so the label names
                            both axes and aria-checked carries the state. */}
                        <button
                          type="button"
                          role="switch"
                          aria-checked={isEnabled(et, ch.key)}
                          aria-label={t('pages.notificationPreferences.toggleLabel', {
                            channel: t(`pages.notificationPreferences.channels.${ch.key}`),
                            event: t(`pages.notificationPreferences.events.${et}`),
                          })}
                          onClick={() => toggle(et, ch.key)}
                          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            isEnabled(et, ch.key) ? 'bg-primary' : 'bg-muted'
                          }`}
                        >
                          <span
                            aria-hidden="true"
                            className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                              isEnabled(et, ch.key) ? 'translate-x-6' : 'translate-x-1'
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
