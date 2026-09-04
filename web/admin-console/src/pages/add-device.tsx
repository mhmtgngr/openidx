import { useState, useMemo, useCallback } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { QRCodeCanvas } from 'qrcode.react'
import { useNavigate } from 'react-router-dom'
import { Trans, useTranslation } from 'react-i18next'
import { Laptop, Smartphone, Apple, Monitor, Copy, CheckCircle2, Loader2, ArrowLeft } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'
import { QueryError } from '../components/query-error'

type OSKey = 'windows' | 'macos' | 'linux' | 'android' | 'ios'

/** Operating-system names are product names, so they render as they are. */
const OSES: { key: OSKey; label: string; icon: typeof Laptop }[] = [
  { key: 'windows', label: 'Windows', icon: Monitor },
  { key: 'macos', label: 'macOS', icon: Apple },
  { key: 'linux', label: 'Linux', icon: Laptop },
  { key: 'android', label: 'Android', icon: Smartphone },
  { key: 'ios', label: 'iPhone / iPad', icon: Apple },
]

/**
 * Platforms with no published client. iOS builds in CI but is never
 * distributed (no Apple credentials), and there is no macOS installer target at
 * all -- `agent/Makefile` cross-compiles a darwin binary, nothing packages it.
 * A manifest entry still wins: the day a build exists and lands in
 * AGENT_DOWNLOADS_DIR, the download button appears and this copy stops being
 * reached.
 */
const NO_PUBLISHED_CLIENT = new Set<OSKey>(['ios', 'macos'])

function detectOS(): OSKey {
  const ua = navigator.userAgent.toLowerCase()
  if (/android/.test(ua)) return 'android'
  if (/iphone|ipad|ipod/.test(ua)) return 'ios'
  if (/mac os x/.test(ua)) return 'macos'
  if (/linux/.test(ua)) return 'linux'
  return 'windows'
}

interface EnrollSession {
  id: string
  code: string
  deep_link: string
  server: string
  expires_at: string
}

interface AgentManifestEntry {
  url: string
  version?: string
}

export function AddDevicePage() {
  const navigate = useNavigate()
  const { t } = useTranslation()
  const { toast } = useToast()
  const [os, setOs] = useState<OSKey>(detectOS())

  // Per-OS installer manifest (Phase 2 populates /downloads/agent-manifest.json).
  // Absent today → the wizard still works; we just skip the download button.
  const { data: manifest } = useQuery({
    queryKey: ['agent-manifest'],
    queryFn: () => api.get<Record<string, AgentManifestEntry>>('/downloads/agent-manifest.json'),
    retry: false,
    staleTime: 5 * 60_000,
  })
  const installer = manifest?.[os]

  // Create an enrollment session on demand ("Connect this device").
  const createSession = useMutation({
    mutationFn: () => api.post<EnrollSession>('/api/v1/access/agent/enroll/session', {}),
    onError: (e: Error) =>
      toast({
        title: t('pages.addDevice.startFailed'),
        description: e.message,
        variant: 'destructive',
      }),
  })
  const session = createSession.data

  // Poll the session until the device connects.
  const { data: status, isError, error } = useQuery({
    queryKey: ['enroll-session-status', session?.id],
    queryFn: () =>
      api.get<{ status: string; agent_id: string; device_trusted: boolean }>(
        `/api/v1/access/agent/enroll/session/${session!.id}/status`
      ),
    enabled: !!session?.id,
    refetchInterval: (q) =>
      (q.state.data as { status?: string } | undefined)?.status === 'enrolled' ? false : 3000,
  })
  const done = status?.status === 'enrolled'

  const copy = useCallback(
    (text: string, what: string) => {
      navigator.clipboard.writeText(text)
      toast({
        title: t('common.copied'),
        description: t('pages.addDevice.copiedItem', { what }),
      })
    },
    [toast, t]
  )

  const androidNote = useMemo(() => os === 'android' || os === 'ios', [os])

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <Button variant="ghost" size="sm" className="mb-2 -ml-2" onClick={() => navigate('/my-devices')}>
          <ArrowLeft className="mr-1.5 h-4 w-4" /> {t('nav.items.myDevices')}
        </Button>
        <h1 className="text-2xl font-bold tracking-tight">
          {t('pages.addDevice.title')}
        </h1>
        <p className="text-muted-foreground">
          {t('pages.addDevice.subtitle')}
        </p>
      </div>

      {/* Step 1 — pick the OS */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t('pages.addDevice.step1')}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {OSES.map(({ key, label, icon: Icon }) => (
              <Button
                key={key}
                variant={os === key ? 'default' : 'outline'}
                size="sm"
                onClick={() => setOs(key)}
              >
                <Icon className="mr-1.5 h-4 w-4" /> {label}
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Step 2 — get the app */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t('pages.addDevice.step2')}</CardTitle>
          <CardDescription>
            {androidNote
              ? t('pages.addDevice.step2Mobile')
              : t('pages.addDevice.step2Desktop')}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          {installer ? (
            <Button asChild size="sm">
              <a href={installer.url}>
                {t('pages.addDevice.download', {
                  os: OSES.find((o) => o.key === os)?.label,
                })}
              </a>
            </Button>
          ) : (
            <p className="text-sm text-muted-foreground">
              {/* Two different truths. Windows, Linux and Android are built and
                  released (agent-v* publishes the MSI, the deb/rpm pair and the
                  APK) -- if there is no download button, this deployment has
                  not put them in AGENT_DOWNLOADS_DIR. iOS and macOS have no
                  published client at all, so telling the user to ask an
                  administrator for one sends them after something nobody has. */}
              {t(
                NO_PUBLISHED_CLIENT.has(os)
                  ? 'pages.addDevice.installerNoBuild'
                  : 'pages.addDevice.installerFromAdmin',
                { os: OSES.find((o) => o.key === os)?.label }
              )}
            </p>
          )}
        </CardContent>
      </Card>

      {/* Step 3 — connect */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t('pages.addDevice.step3')}</CardTitle>
        </CardHeader>
        <CardContent>
          {!session ? (
            <Button onClick={() => createSession.mutate()} disabled={createSession.isPending}>
              {createSession.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('pages.addDevice.generate')}
            </Button>
          ) : done ? (
            <div className="flex flex-col items-center gap-3 py-6 text-center">
              <CheckCircle2 className="h-12 w-12 text-green-600" />
              <p className="text-lg font-medium">{t('pages.addDevice.connected')}</p>
              <Badge variant={status?.device_trusted ? 'default' : 'secondary'}>
                {status?.device_trusted
                  ? t('pages.addDevice.trusted')
                  : t('pages.addDevice.pendingTrust')}
              </Badge>
              <Button className="mt-2" onClick={() => navigate('/my-devices')}>
                {t('pages.addDevice.done')}
              </Button>
            </div>
          ) : isError ? (
            <QueryError error={error} resource={t('pages.addDevice.resource')} />
          ) : (
            <div className="flex flex-col items-center gap-4">
              {/* The code is short — the easiest path is to just type it in the
                  OpenIDX app (or tap "Open in app" on this phone). Scanning is
                  the secondary option. */}
              <p className="text-sm text-muted-foreground text-center">
                <Trans
                  i18nKey="pages.addDevice.typeCode"
                  components={[<span key="0" className="font-medium" />]}
                />
              </p>
              {/* Big, grouped, selectable code — the primary path. Display is
                  grouped for readability; copy emits the raw code. */}
              <button
                type="button"
                onClick={() => copy(session.code, t('pages.addDevice.enrollmentCode'))}
                className="rounded-lg border bg-muted px-6 py-4 text-center font-mono text-2xl font-semibold tracking-[0.2em] select-all hover:bg-muted/70"
                title={t('pages.addDevice.clickToCopy')}
              >
                {(session.code.match(/.{1,4}/g) ?? [session.code]).join('-')}
              </button>
              <div className="flex flex-wrap justify-center gap-2">
                <Button asChild>
                  <a href={session.deep_link}>{t('pages.addDevice.openInApp')}</a>
                </Button>
                <Button
                  variant="outline"
                  onClick={() => copy(session.code, t('pages.addDevice.enrollmentCode'))}
                >
                  <Copy className="mr-1.5 h-3.5 w-3.5" /> {t('pages.addDevice.copyCode')}
                </Button>
              </div>
              <details className="text-sm text-muted-foreground">
                <summary className="cursor-pointer">{t('pages.addDevice.showQr')}</summary>
                <div className="mt-3 flex flex-col items-center gap-2">
                  <div className="rounded-lg border bg-background p-4">
                    <QRCodeCanvas value={session.deep_link} size={240} level="H" includeMargin />
                  </div>
                  <span>{t('pages.addDevice.scanHint')}</span>
                </div>
              </details>
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />{' '}
                {t('pages.addDevice.waiting')}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
