import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Smartphone, Plus, Trash2, Loader2, Bell, QrCode } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { useToast } from '../hooks/use-toast'
import { api, PushMFADevice, PushMFAEnrollment } from '../lib/api'

export function PushDevicesPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [devices, setDevices] = useState<PushMFADevice[]>([])
  const [loading, setLoading] = useState(true)
  const [showEnrollForm, setShowEnrollForm] = useState(false)
  const [enrolling, setEnrolling] = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)

  // QR self-enrollment state (Google/MS-Authenticator style).
  const [qrPayload, setQrPayload] = useState<string | null>(null)
  const [qrExpiresAt, setQrExpiresAt] = useState<number>(0)
  const [qrLoading, setQrLoading] = useState(false)

  // Enrollment form state
  const [deviceName, setDeviceName] = useState('')
  const [deviceModel, setDeviceModel] = useState('')
  const [platform, setPlatform] = useState<'ios' | 'android' | 'web'>('web')
  const [deviceToken, setDeviceToken] = useState('')

  const fetchDevices = async () => {
    try {
      setLoading(true)
      const data = await api.getPushDevices()
      setDevices(data || [])
    } catch {
      toast({
        title: t('common.error'),
        description: t('pages.pushDevices.toasts.loadFailed'),
        variant: 'destructive',
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDevices()
  }, [])

  const handleEnroll = async () => {
    if (!deviceName.trim() || !deviceToken.trim()) return

    try {
      setEnrolling(true)
      const enrollment: PushMFAEnrollment = {
        device_token: deviceToken,
        platform,
        device_name: deviceName,
        device_model: deviceModel || undefined,
      }
      await api.registerPushDevice(enrollment)
      toast({ title: t('common.success'), description: t('pages.pushDevices.toasts.enrolled') })
      setShowEnrollForm(false)
      setDeviceName('')
      setDeviceModel('')
      setDeviceToken('')
      fetchDevices()
    } catch {
      toast({
        title: t('common.error'),
        description: t('pages.pushDevices.toasts.enrollFailed'),
        variant: 'destructive',
      })
    } finally {
      setEnrolling(false)
    }
  }

  // startQrEnrollment mints an enrollment ticket and shows the QR the
  // authenticator app scans. We then poll the device list so the card can
  // auto-dismiss once the phone completes enrollment.
  const startQrEnrollment = async () => {
    try {
      setQrLoading(true)
      setShowEnrollForm(false)
      const ticket = await api.startPushEnrollment()
      setQrPayload(ticket.qr_payload)
      setQrExpiresAt(Date.now() + ticket.expires_in * 1000)
    } catch {
      toast({
        title: t('common.error'),
        description: t('pages.pushDevices.toasts.qrFailed'),
        variant: 'destructive',
      })
    } finally {
      setQrLoading(false)
    }
  }

  const cancelQrEnrollment = () => {
    setQrPayload(null)
    setQrExpiresAt(0)
  }

  // While a QR is showing, poll for the new device and expire the ticket.
  useEffect(() => {
    if (!qrPayload) return
    const before = devices.length
    const interval = setInterval(async () => {
      if (Date.now() > qrExpiresAt) {
        setQrPayload(null)
        toast({
          title: t('pages.pushDevices.toasts.qrExpiredTitle'),
          description: t('pages.pushDevices.toasts.qrExpiredDesc'),
        })
        return
      }
      try {
        const data = await api.getPushDevices()
        if ((data?.length || 0) > before) {
          setDevices(data || [])
          setQrPayload(null)
          toast({
            title: t('pages.pushDevices.toasts.deviceEnrolledTitle'),
            description: t('pages.pushDevices.toasts.deviceEnrolledDesc'),
          })
        }
      } catch {
        // transient; keep polling until expiry
      }
    }, 3000)
    return () => clearInterval(interval)
  }, [qrPayload, qrExpiresAt, devices.length, toast, t])

  const handleDelete = async (deviceId: string) => {
    try {
      setDeleting(deviceId)
      await api.deletePushDevice(deviceId)
      toast({ title: t('common.success'), description: t('pages.pushDevices.toasts.removed') })
      setDevices(devices.filter(d => d.id !== deviceId))
    } catch {
      toast({
        title: t('common.error'),
        description: t('pages.pushDevices.toasts.removeFailed'),
        variant: 'destructive',
      })
    } finally {
      setDeleting(null)
    }
  }

  const getPlatformLabel = (p: string) => {
    switch (p) {
      case 'ios': return t('pages.pushDevices.platforms.ios')
      case 'android': return t('pages.pushDevices.platforms.android')
      case 'web': return t('pages.pushDevices.platforms.web')
      default: return p
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.pushDevices.title')}</h1>
          <p className="text-muted-foreground">{t('pages.pushDevices.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={startQrEnrollment} disabled={qrLoading || !!qrPayload}>
            {qrLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <QrCode className="mr-2 h-4 w-4" />}
            {t('pages.pushDevices.enrollViaApp')}
          </Button>
          <Button variant="outline" onClick={() => setShowEnrollForm(true)} disabled={showEnrollForm}>
            <Plus className="mr-2 h-4 w-4" /> {t('pages.pushDevices.manualEnroll')}
          </Button>
        </div>
      </div>

      {qrPayload && (
        <Card>
          <CardHeader>
            <CardTitle>{t('pages.pushDevices.qr.title')}</CardTitle>
            <CardDescription>{t('pages.pushDevices.qr.description')}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-4">
            <div className="rounded-lg bg-background p-4">
              <QRCodeSVG value={qrPayload} size={200} />
            </div>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> {t('pages.pushDevices.qr.waiting')}
            </div>
            <Button variant="ghost" onClick={cancelQrEnrollment}>{t('common.cancel')}</Button>
          </CardContent>
        </Card>
      )}

      {showEnrollForm && (
        <Card>
          <CardHeader>
            <CardTitle>{t('pages.pushDevices.enrollCard.title')}</CardTitle>
            <CardDescription>{t('pages.pushDevices.enrollCard.description')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="device-name">{t('pages.pushDevices.enrollCard.deviceName')}</Label>
                <Input
                  id="device-name"
                  placeholder={t('pages.pushDevices.enrollCard.deviceNamePlaceholder')}
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  disabled={enrolling}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-model">{t('pages.pushDevices.enrollCard.deviceModel')}</Label>
                <Input
                  id="device-model"
                  placeholder={t('pages.pushDevices.enrollCard.deviceModelPlaceholder')}
                  value={deviceModel}
                  onChange={(e) => setDeviceModel(e.target.value)}
                  disabled={enrolling}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="platform">{t('pages.pushDevices.enrollCard.platform')}</Label>
                <select
                  id="platform"
                  className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  value={platform}
                  onChange={(e) => setPlatform(e.target.value as 'ios' | 'android' | 'web')}
                  disabled={enrolling}
                >
                  <option value="web">{t('pages.pushDevices.platforms.web')}</option>
                  <option value="ios">{t('pages.pushDevices.platforms.ios')}</option>
                  <option value="android">{t('pages.pushDevices.platforms.android')}</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="device-token">{t('pages.pushDevices.enrollCard.deviceToken')}</Label>
                <Input
                  id="device-token"
                  placeholder={t('pages.pushDevices.enrollCard.deviceTokenPlaceholder')}
                  value={deviceToken}
                  onChange={(e) => setDeviceToken(e.target.value)}
                  disabled={enrolling}
                />
              </div>
            </div>
            <div className="flex gap-2">
              <Button onClick={handleEnroll} disabled={enrolling || !deviceName.trim() || !deviceToken.trim()}>
                {enrolling ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t('pages.pushDevices.enrollCard.enrolling')}
                  </span>
                ) : (
                  t('pages.pushDevices.enrollCard.submit')
                )}
              </Button>
              <Button variant="outline" onClick={() => setShowEnrollForm(false)} disabled={enrolling}>
                {t('common.cancel')}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-5 w-5" />
            {t('pages.pushDevices.listTitle')}
          </CardTitle>
          <CardDescription>
            {t('pages.pushDevices.count', { count: devices.length })}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : devices.length === 0 ? (
            <div className="text-center py-8">
              <Bell className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground">{t('pages.pushDevices.empty')}</p>
              <p className="text-sm text-muted-foreground mt-1">{t('pages.pushDevices.emptyHint')}</p>
            </div>
          ) : (
            <div className="space-y-3">
              {devices.map((device) => (
                <div
                  key={device.id}
                  className="flex items-center justify-between p-4 border rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-green-100 rounded-lg">
                      <Smartphone className="h-5 w-5 text-green-600" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{device.device_name}</p>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground">
                          {getPlatformLabel(device.platform)}
                        </span>
                        {device.enabled ? (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700">
                            {t('pages.pushDevices.active')}
                          </span>
                        ) : (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700">
                            {t('pages.pushDevices.disabled')}
                          </span>
                        )}
                        {device.trusted && (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">
                            {t('pages.pushDevices.trusted')}
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {device.device_model && <>{device.device_model} &middot; </>}
                        {t('pages.pushDevices.enrolled', {
                          date: new Date(device.created_at).toLocaleDateString(undefined),
                        })}
                        {device.last_used_at && (
                          <>
                            {' '}
                            &middot;{' '}
                            {t('pages.pushDevices.lastUsed', {
                              date: new Date(device.last_used_at).toLocaleDateString(undefined),
                            })}
                          </>
                        )}
                      </p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-600 hover:text-red-700 hover:bg-red-50"
                    onClick={() => handleDelete(device.id)}
                    disabled={deleting === device.id}
                  >
                    {deleting === device.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
