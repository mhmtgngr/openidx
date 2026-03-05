import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Monitor, Smartphone, Download, Copy, FileKey, CheckCircle, Circle,
  ArrowRight, Network, Shield, ExternalLink, QrCode, Apple, Laptop,
  Globe, ChevronDown, ChevronRight, AlertTriangle, Zap,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { api } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ClientPlatform {
  platform: string
  name: string
  description: string
  download_url: string
  version: string
  arch: string
  file_type: string
  setup_steps: string[]
}

interface OnboardingStatus {
  has_identity: boolean
  is_enrolled: boolean
  has_services: boolean
  identity_name?: string
  enrollment_jwt?: string
  setup_step: number
  setup_message: string
}

interface ChecklistItem {
  id: string
  title: string
  description: string
  completed: boolean
  action: string
  priority: number
}

interface SetupChecklist {
  items: ChecklistItem[]
  total: number
  completed: number
  progress: number
}

interface EnrollmentAnalytics {
  total_users: number
  total_identities: number
  enrolled: number
  pending: number
  unsynced: number
  enrollment_rate: number
  recent_enrolled: number
  stale_identities: number
}

// ─── Platform Icons ──────────────────────────────────────────────────────────

const PLATFORM_ICONS: Record<string, React.ElementType> = {
  windows: Monitor,
  macos: Apple,
  linux: Laptop,
  'mobile-ios': Smartphone,
  'mobile-android': Smartphone,
  browser: Globe,
}

const PLATFORM_COLORS: Record<string, string> = {
  windows: 'bg-blue-100 text-blue-700 border-blue-200',
  macos: 'bg-gray-100 text-gray-700 border-gray-200',
  linux: 'bg-orange-100 text-orange-700 border-orange-200',
  'mobile-ios': 'bg-purple-100 text-purple-700 border-purple-200',
  'mobile-android': 'bg-green-100 text-green-700 border-green-200',
  browser: 'bg-cyan-100 text-cyan-700 border-cyan-200',
}

// ─── Page ────────────────────────────────────────────────────────────────────

export function ClientSetupPage() {
  const [activeTab, setActiveTab] = useState('setup')

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Client Setup</h1>
        <p className="text-muted-foreground">
          Get connected to the zero-trust network in minutes
        </p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="setup" className="gap-1.5">
            <Network className="h-4 w-4" />
            My Setup
          </TabsTrigger>
          <TabsTrigger value="downloads" className="gap-1.5">
            <Download className="h-4 w-4" />
            Downloads
          </TabsTrigger>
          <TabsTrigger value="admin" className="gap-1.5">
            <Shield className="h-4 w-4" />
            Admin Dashboard
          </TabsTrigger>
        </TabsList>

        <TabsContent value="setup">
          <UserSetupTab />
        </TabsContent>
        <TabsContent value="downloads">
          <DownloadsTab />
        </TabsContent>
        <TabsContent value="admin">
          <AdminDashboardTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// ─── User Setup Tab ──────────────────────────────────────────────────────────

function UserSetupTab() {
  const { toast } = useToast()
  const [showJwt, setShowJwt] = useState(false)

  const { data: status, isLoading } = useQuery({
    queryKey: ['onboarding-status'],
    queryFn: () => api.get<OnboardingStatus>('/api/v1/access/ziti/onboarding-status'),
    refetchInterval: 10000,
  })

  const { data: platformsResp } = useQuery({
    queryKey: ['client-platforms'],
    queryFn: () => api.get<{ platforms: ClientPlatform[] }>('/api/v1/access/ziti/client-platforms'),
  })

  const platforms = platformsResp?.platforms || []

  const downloadJwt = () => {
    if (!status?.enrollment_jwt) return
    const blob = new Blob([status.enrollment_jwt], { type: 'application/jwt' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${status.identity_name || 'identity'}.jwt`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  const step = status?.setup_step || 0

  const steps = [
    { num: 1, title: 'Identity Created', description: 'Your admin has provisioned a Ziti identity for your account.' },
    { num: 2, title: 'Download Tunneler', description: 'Install the OpenZiti tunneler for your operating system.' },
    { num: 3, title: 'Import JWT Token', description: 'Import your enrollment token into the tunneler to connect.' },
    { num: 4, title: 'Connected!', description: 'You can now access services through the zero-trust overlay.' },
  ]

  return (
    <div className="space-y-6 mt-4">
      {/* Progress Bar */}
      <Card>
        <CardContent className="py-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-semibold">Your Setup Progress</h3>
            <Badge variant={step >= 3 ? 'default' : 'secondary'}>
              {step >= 4 ? 'Connected' : step >= 3 ? 'Enrolled' : `Step ${Math.max(1, step)} of 4`}
            </Badge>
          </div>

          {/* Step indicators */}
          <div className="flex items-center gap-0">
            {steps.map((s, i) => (
              <div key={s.num} className="flex items-center flex-1">
                <div className="flex flex-col items-center flex-1">
                  <div className={`flex items-center justify-center h-10 w-10 rounded-full border-2 transition-all ${
                    step >= s.num
                      ? 'bg-green-100 border-green-500 text-green-700'
                      : step === s.num - 1
                      ? 'bg-blue-100 border-blue-500 text-blue-700 animate-pulse'
                      : 'bg-muted border-muted-foreground/30 text-muted-foreground'
                  }`}>
                    {step >= s.num ? (
                      <CheckCircle className="h-5 w-5" />
                    ) : (
                      <span className="text-sm font-bold">{s.num}</span>
                    )}
                  </div>
                  <p className={`text-xs font-medium mt-1.5 text-center ${step >= s.num ? 'text-green-700' : 'text-muted-foreground'}`}>
                    {s.title}
                  </p>
                  <p className="text-[10px] text-muted-foreground text-center max-w-[140px] mt-0.5">{s.description}</p>
                </div>
                {i < steps.length - 1 && (
                  <div className={`h-0.5 w-full mx-1 mt-[-24px] ${step > s.num ? 'bg-green-500' : 'bg-muted-foreground/20'}`} />
                )}
              </div>
            ))}
          </div>

          <p className="mt-4 text-sm text-center text-muted-foreground">{status?.setup_message}</p>
        </CardContent>
      </Card>

      {/* No Identity State */}
      {step === 0 && (
        <Card className="border-amber-200 bg-amber-50/30">
          <CardContent className="py-8 text-center">
            <AlertTriangle className="h-12 w-12 text-amber-500 mx-auto mb-3" />
            <h3 className="text-lg font-semibold">No Identity Provisioned</h3>
            <p className="text-muted-foreground mt-1 max-w-md mx-auto">
              Your account doesn&apos;t have a Ziti network identity yet. Contact your administrator
              to sync your account, or they can do it from the Ziti Network &gt; Identities tab.
            </p>
          </CardContent>
        </Card>
      )}

      {/* JWT Available — Show Download & Instructions */}
      {step >= 1 && step < 3 && status?.enrollment_jwt && (
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Enrollment Token */}
          <Card className="border-blue-200 bg-blue-50/30">
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <FileKey className="h-4 w-4" />
                Your Enrollment Token
              </CardTitle>
              <CardDescription>
                This one-time token connects your device to the zero-trust network.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-2">
                <Button onClick={downloadJwt}>
                  <Download className="mr-2 h-4 w-4" /> Download .jwt File
                </Button>
                <Button variant="outline" onClick={() => {
                  navigator.clipboard.writeText(status.enrollment_jwt!)
                  toast({ title: 'Copied!', description: 'JWT token copied to clipboard.' })
                }}>
                  <Copy className="mr-2 h-4 w-4" /> Copy Token
                </Button>
                <Button variant="outline" onClick={() => setShowJwt(!showJwt)}>
                  <QrCode className="mr-2 h-4 w-4" /> {showJwt ? 'Hide' : 'Show'} Token
                </Button>
              </div>
              {showJwt && (
                <textarea
                  readOnly
                  value={status.enrollment_jwt}
                  className="w-full h-20 rounded-md border bg-white p-2 text-xs font-mono"
                />
              )}
              <p className="text-xs text-muted-foreground flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                This token can only be used once. Keep it secure.
              </p>
            </CardContent>
          </Card>

          {/* Quick Start */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Zap className="h-4 w-4" />
                Quick Start
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="space-y-3">
                <li className="flex items-start gap-3">
                  <span className="flex items-center justify-center h-6 w-6 rounded-full bg-blue-100 text-blue-700 text-xs font-bold shrink-0">1</span>
                  <div>
                    <p className="text-sm font-medium">Download the tunneler</p>
                    <p className="text-xs text-muted-foreground">Choose your platform from the Downloads tab below.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <span className="flex items-center justify-center h-6 w-6 rounded-full bg-blue-100 text-blue-700 text-xs font-bold shrink-0">2</span>
                  <div>
                    <p className="text-sm font-medium">Import the .jwt file</p>
                    <p className="text-xs text-muted-foreground">Open the tunneler, click &quot;Add Identity&quot;, and select the downloaded .jwt file.</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <span className="flex items-center justify-center h-6 w-6 rounded-full bg-blue-100 text-blue-700 text-xs font-bold shrink-0">3</span>
                  <div>
                    <p className="text-sm font-medium">You&apos;re connected!</p>
                    <p className="text-xs text-muted-foreground">The tunneler enrolls automatically and you can access all authorized services.</p>
                  </div>
                </li>
              </ol>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Already Enrolled */}
      {step >= 3 && (
        <Card className="border-green-200 bg-green-50/30">
          <CardContent className="py-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-full bg-green-100">
                <CheckCircle className="h-8 w-8 text-green-600" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-green-800">You&apos;re Connected!</h3>
                <p className="text-sm text-green-700">
                  Identity <strong>{status?.identity_name}</strong> is enrolled and active.
                  {status?.has_services && ' You have access to zero-trust services.'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Platform Downloads (compact) */}
      {step >= 1 && step < 3 && platforms.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold mb-3">Download a Tunneler</h3>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {platforms.filter(p => p.platform !== 'browser').map((p) => {
              const Icon = PLATFORM_ICONS[p.platform] || Monitor
              const color = PLATFORM_COLORS[p.platform] || 'bg-gray-100 text-gray-700 border-gray-200'
              return (
                <Card key={p.platform} className={`border ${color.split(' ').pop()}`}>
                  <CardContent className="py-4">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg ${color.split(' ').slice(0, 2).join(' ')}`}>
                        <Icon className="h-5 w-5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium">{p.name}</p>
                        <p className="text-xs text-muted-foreground">{p.arch} &middot; {p.file_type}</p>
                      </div>
                      {p.download_url && (
                        <a href={p.download_url} target="_blank" rel="noopener noreferrer">
                          <Button size="sm" variant="outline">
                            <Download className="h-3.5 w-3.5" />
                          </Button>
                        </a>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Downloads Tab ───────────────────────────────────────────────────────────

function DownloadsTab() {
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data: platformsResp, isLoading } = useQuery({
    queryKey: ['client-platforms'],
    queryFn: () => api.get<{ platforms: ClientPlatform[] }>('/api/v1/access/ziti/client-platforms'),
  })

  const platforms = platformsResp?.platforms || []

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-4 mt-4">
      <p className="text-sm text-muted-foreground">
        Choose your platform and follow the step-by-step instructions to connect.
      </p>

      {platforms.map((p) => {
        const Icon = PLATFORM_ICONS[p.platform] || Monitor
        const color = PLATFORM_COLORS[p.platform] || 'bg-gray-100 text-gray-700 border-gray-200'
        const isExpanded = expanded === p.platform

        return (
          <Card key={p.platform}>
            <button
              className="w-full text-left"
              onClick={() => setExpanded(isExpanded ? null : p.platform)}
            >
              <CardContent className="py-4">
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-lg ${color.split(' ').slice(0, 2).join(' ')}`}>
                    <Icon className="h-6 w-6" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-semibold">{p.name}</p>
                    <p className="text-sm text-muted-foreground">{p.description}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="text-xs">{p.arch}</Badge>
                      <Badge variant="outline" className="text-xs">{p.file_type}</Badge>
                      <Badge variant="outline" className="text-xs">v{p.version}</Badge>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {p.download_url && (
                      <a
                        href={p.download_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Button size="sm">
                          <Download className="mr-2 h-4 w-4" /> Download
                        </Button>
                      </a>
                    )}
                    {isExpanded ? <ChevronDown className="h-5 w-5 text-muted-foreground" /> : <ChevronRight className="h-5 w-5 text-muted-foreground" />}
                  </div>
                </div>
              </CardContent>
            </button>

            {isExpanded && (
              <div className="px-6 pb-5 border-t">
                <h4 className="text-sm font-semibold mt-4 mb-3">Setup Instructions</h4>
                <ol className="space-y-2.5">
                  {p.setup_steps.map((step, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <span className="flex items-center justify-center h-6 w-6 rounded-full bg-primary/10 text-primary text-xs font-bold shrink-0 mt-0.5">
                        {i + 1}
                      </span>
                      <p className="text-sm">{step}</p>
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </Card>
        )
      })}

      {/* Troubleshooting */}
      <Card className="border-amber-200">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            Troubleshooting
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex items-start gap-2">
            <ArrowRight className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
            <span><strong>Token expired?</strong> Contact your administrator for a new enrollment JWT.</span>
          </div>
          <div className="flex items-start gap-2">
            <ArrowRight className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
            <span><strong>Can&apos;t connect?</strong> Verify the tunneler is running and your network allows outbound connections to the Ziti controller.</span>
          </div>
          <div className="flex items-start gap-2">
            <ArrowRight className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
            <span><strong>macOS: Network extension?</strong> Go to System Settings &gt; Privacy &amp; Security &gt; Network Extensions and enable the Ziti extension.</span>
          </div>
          <div className="flex items-start gap-2">
            <ArrowRight className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />
            <span><strong>Linux: Permission denied?</strong> Run <code className="bg-muted px-1 rounded text-xs">sudo</code> for enrollment and service commands.</span>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── Admin Dashboard Tab ─────────────────────────────────────────────────────

function AdminDashboardTab() {
  const { data: analytics, isLoading: analyticsLoading } = useQuery({
    queryKey: ['enrollment-analytics'],
    queryFn: () => api.get<EnrollmentAnalytics>('/api/v1/access/ziti/enrollment-analytics'),
    refetchInterval: 15000,
  })

  const { data: checklist, isLoading: checklistLoading } = useQuery({
    queryKey: ['setup-checklist'],
    queryFn: () => api.get<SetupChecklist>('/api/v1/access/ziti/setup-checklist'),
    refetchInterval: 30000,
  })

  if (analyticsLoading || checklistLoading) {
    return (
      <div className="flex justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6 mt-4">
      {/* Enrollment Analytics */}
      {analytics && (
        <>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardContent className="py-4">
                <p className="text-xs font-medium text-muted-foreground">Enrollment Rate</p>
                <div className="flex items-end gap-2 mt-1">
                  <span className="text-3xl font-bold">{Math.round(analytics.enrollment_rate)}%</span>
                  <span className="text-sm text-muted-foreground mb-1">of users</span>
                </div>
                <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      analytics.enrollment_rate >= 80 ? 'bg-green-500' :
                      analytics.enrollment_rate >= 50 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${Math.min(100, analytics.enrollment_rate)}%` }}
                  />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-4">
                <p className="text-xs font-medium text-muted-foreground">Enrolled</p>
                <p className="text-3xl font-bold text-green-600 mt-1">{analytics.enrolled}</p>
                <p className="text-xs text-muted-foreground">of {analytics.total_identities} identities</p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-4">
                <p className="text-xs font-medium text-muted-foreground">Pending</p>
                <p className="text-3xl font-bold text-amber-600 mt-1">{analytics.pending}</p>
                <p className="text-xs text-muted-foreground">awaiting enrollment</p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="py-4">
                <p className="text-xs font-medium text-muted-foreground">No Identity</p>
                <p className="text-3xl font-bold text-red-600 mt-1">{analytics.unsynced}</p>
                <p className="text-xs text-muted-foreground">users without Ziti identities</p>
              </CardContent>
            </Card>
          </div>

          {/* Secondary stats */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="border-green-200">
              <CardContent className="py-3 flex items-center gap-3">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <div>
                  <p className="text-sm font-medium">{analytics.recent_enrolled} enrolled this week</p>
                  <p className="text-xs text-muted-foreground">last 7 days</p>
                </div>
              </CardContent>
            </Card>
            <Card className={analytics.stale_identities > 0 ? 'border-amber-200' : ''}>
              <CardContent className="py-3 flex items-center gap-3">
                <AlertTriangle className={`h-5 w-5 ${analytics.stale_identities > 0 ? 'text-amber-600' : 'text-muted-foreground'}`} />
                <div>
                  <p className="text-sm font-medium">{analytics.stale_identities} stale identities</p>
                  <p className="text-xs text-muted-foreground">created &gt;30 days ago, never enrolled</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="py-3 flex items-center gap-3">
                <Network className="h-5 w-5 text-blue-600" />
                <div>
                  <p className="text-sm font-medium">{analytics.total_users} total users</p>
                  <p className="text-xs text-muted-foreground">{analytics.total_identities} Ziti identities</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </>
      )}

      {/* Setup Checklist */}
      {checklist && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Deployment Checklist
              </span>
              <Badge variant={checklist.progress === 100 ? 'default' : 'secondary'}>
                {checklist.completed}/{checklist.total} complete
              </Badge>
            </CardTitle>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all"
                style={{ width: `${checklist.progress}%` }}
              />
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {checklist.items.map((item) => (
                <div
                  key={item.id}
                  className={`flex items-center gap-3 p-3 rounded-lg border ${
                    item.completed ? 'bg-green-50/50 border-green-200' : 'bg-muted/30'
                  }`}
                >
                  {item.completed ? (
                    <CheckCircle className="h-5 w-5 text-green-600 shrink-0" />
                  ) : (
                    <Circle className="h-5 w-5 text-muted-foreground shrink-0" />
                  )}
                  <div className="flex-1 min-w-0">
                    <p className={`text-sm font-medium ${item.completed ? 'text-green-800' : ''}`}>
                      {item.title}
                    </p>
                    <p className="text-xs text-muted-foreground">{item.description}</p>
                  </div>
                  {!item.completed && (
                    <a href={item.action}>
                      <Button size="sm" variant="outline">
                        <ArrowRight className="h-3.5 w-3.5" />
                      </Button>
                    </a>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
