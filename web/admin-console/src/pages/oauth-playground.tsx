import { useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import {
  Play,
  CheckCircle2,
  Circle,
  Copy,
  ExternalLink,
  KeyRound,
  ShieldCheck,
  ArrowRightLeft,
  User,
  Loader2,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Textarea } from '../components/ui/textarea'
import { Badge } from '../components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '../components/ui/card'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs'
import { api, baseURL } from '../lib/api'
import { useToast } from '../hooks/use-toast'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PlaygroundSession {
  session_id: string
  code_verifier: string
  code_challenge: string
  state: string
  authorize_url: string
  client_id: string
  redirect_uri: string
}

interface TokenResponse {
  access_token: string
  id_token: string
  token_type: string
  expires_in: number
  refresh_token?: string
  scope?: string
}

interface UserInfoResponse {
  sub: string
  email?: string
  name?: string
  preferred_username?: string
  [key: string]: unknown
}

interface DecodedJWT {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  expires_at?: string
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function decodeJWT(token: string): DecodedJWT | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')))
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
    const expiresAt = payload.exp
      ? new Date(payload.exp * 1000).toISOString()
      : undefined
    return { header, payload, expires_at: expiresAt }
  } catch {
    return null
  }
}

function formatJSON(obj: unknown): string {
  return JSON.stringify(obj, null, 2)
}

// ---------------------------------------------------------------------------
// Step indicator
// ---------------------------------------------------------------------------

function StepHeader({
  label,
  description,
  completed,
  active,
  icon: Icon,
}: {
  /** Already-localized "Step N: Title" line. */
  label: string
  description: string
  completed: boolean
  active: boolean
  icon: React.ElementType
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="flex-shrink-0 mt-0.5">
        {completed ? (
          <CheckCircle2 className="h-6 w-6 text-green-600" />
        ) : active ? (
          <Icon className="h-6 w-6 text-primary" />
        ) : (
          <Circle className="h-6 w-6 text-muted-foreground" />
        )}
      </div>
      <div>
        <CardTitle className="text-base">{label}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function OAuthPlaygroundPage() {
  const { t } = useTranslation()
  const { toast } = useToast()

  // Flow state
  const [session, setSession] = useState<PlaygroundSession | null>(null)
  const [authCode, setAuthCode] = useState('')
  const [tokenData, setTokenData] = useState<TokenResponse | null>(null)
  const [userInfo, setUserInfo] = useState<UserInfoResponse | null>(null)

  // JWT decoder state
  const [jwtInput, setJwtInput] = useState('')
  const [decodedJwt, setDecodedJwt] = useState<DecodedJWT | null>(null)

  // Completed steps tracking
  const step1Done = !!session
  const step2Done = !!authCode
  const step3Done = !!tokenData
  const step4Done = !!userInfo

  const currentStep = step4Done ? 5 : step3Done ? 4 : step2Done ? 3 : step1Done ? 2 : 1

  // --- Step 1: Create session ---
  const createSessionMutation = useMutation({
    mutationFn: () =>
      api.post<PlaygroundSession>(
        '/api/v1/developer/playground/sessions',
        // Send the redirect_uri derived from this console's origin so the
        // authorize step and the token exchange (which both reuse the stored
        // value) stay consistent, and so it matches a URI registered on
        // playground-client.
        { redirect_uri: `${baseURL}/oauth/callback` }
      ),
    onSuccess: (data) => {
      setSession(data)
      setAuthCode('')
      setTokenData(null)
      setUserInfo(null)
      toast({
        title: t('pages.oauthPlayground.step1.created'),
        description: t('pages.oauthPlayground.step1.createdDesc'),
      })
    },
    onError: (error: Error) => {
      toast({
        title: t('common.error'),
        description: error.message || t('pages.oauthPlayground.step1.failed'),
        variant: 'destructive',
      })
    },
  })

  // --- Step 3: Exchange token ---
  const exchangeTokenMutation = useMutation({
    mutationFn: () =>
      api.post<TokenResponse>(
        '/api/v1/developer/playground/execute',
        {
          session_id: session!.session_id,
          action: 'exchange_token',
          authorization_code: authCode,
          code_verifier: session!.code_verifier,
        }
      ),
    onSuccess: (data) => {
      setTokenData(data)
      setUserInfo(null)
      toast({
        title: t('pages.oauthPlayground.step3.received'),
        description: t('pages.oauthPlayground.step3.receivedDesc'),
      })
    },
    onError: (error: Error) => {
      toast({
        title: t('pages.oauthPlayground.step3.failedTitle'),
        description: error.message || t('pages.oauthPlayground.step3.failed'),
        variant: 'destructive',
      })
    },
  })

  // --- Step 4: UserInfo ---
  const userInfoMutation = useMutation({
    mutationFn: () =>
      api.post<UserInfoResponse>(
        '/api/v1/developer/playground/execute',
        {
          session_id: session!.session_id,
          action: 'userinfo',
          access_token: tokenData!.access_token,
        }
      ),
    onSuccess: (data) => {
      setUserInfo(data)
      toast({
        title: t('pages.oauthPlayground.step4.retrieved'),
        description: t('pages.oauthPlayground.step4.retrievedDesc'),
      })
    },
    onError: (error: Error) => {
      toast({
        title: t('pages.oauthPlayground.step4.failedTitle'),
        description: error.message || t('pages.oauthPlayground.step4.failed'),
        variant: 'destructive',
      })
    },
  })

  // JWT decode handler
  const handleDecodeJWT = useCallback(() => {
    const result = decodeJWT(jwtInput.trim())
    if (result) {
      setDecodedJwt(result)
    } else {
      toast({
        title: t('pages.oauthPlayground.jwt.invalid'),
        description: t('pages.oauthPlayground.jwt.invalidDesc'),
        variant: 'destructive',
      })
    }
  }, [jwtInput, toast, t])

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: t('pages.oauthPlayground.copied'),
      description: t('pages.oauthPlayground.copiedDesc'),
    })
  }

  const resetFlow = () => {
    setSession(null)
    setAuthCode('')
    setTokenData(null)
    setUserInfo(null)
  }

  // Construct the authorize URL for display
  const authorizeUrl = session
    ? `${baseURL}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(session.client_id)}&state=${encodeURIComponent(session.state)}&code_challenge=${encodeURIComponent(session.code_challenge)}&code_challenge_method=S256&redirect_uri=${encodeURIComponent(session.redirect_uri)}`
    : ''

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t('pages.oauthPlayground.title')}</h1>
          <p className="text-muted-foreground">{t('pages.oauthPlayground.subtitle')}</p>
        </div>
        <Button variant="outline" onClick={resetFlow}>
          {t('pages.oauthPlayground.reset')}
        </Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left: flow steps */}
        <div className="lg:col-span-2 space-y-4">
          {/* Step 1: Create Session */}
          <Card className={currentStep === 1 ? 'ring-2 ring-blue-200' : ''}>
            <CardHeader>
              <StepHeader
                label={t('pages.oauthPlayground.stepLabel', {
                  step: 1,
                  title: t('pages.oauthPlayground.step1.title'),
                })}
                description={t('pages.oauthPlayground.step1.desc')}
                completed={step1Done}
                active={currentStep === 1}
                icon={KeyRound}
              />
            </CardHeader>
            <CardContent className="space-y-3">
              <Button
                onClick={() => createSessionMutation.mutate()}
                disabled={createSessionMutation.isPending}
              >
                {createSessionMutation.isPending ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Play className="mr-2 h-4 w-4" />
                )}
                {step1Done
                  ? t('pages.oauthPlayground.step1.regenerate')
                  : t('pages.oauthPlayground.step1.create')}
              </Button>
              {session && (
                <div className="space-y-2 text-xs">
                  <div className="space-y-1">
                    <label className="text-sm font-medium">code_verifier</label>
                    <div className="flex gap-1">
                      <code className="flex-1 bg-muted p-2 rounded font-mono break-all">
                        {session.code_verifier}
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(session.code_verifier)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm font-medium">code_challenge</label>
                    <div className="flex gap-1">
                      <code className="flex-1 bg-muted p-2 rounded font-mono break-all">
                        {session.code_challenge}
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(session.code_challenge)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm font-medium">state</label>
                    <div className="flex gap-1">
                      <code className="flex-1 bg-muted p-2 rounded font-mono break-all">
                        {session.state}
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(session.state)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Step 2: Authorize */}
          <Card
            className={
              currentStep === 2
                ? 'ring-2 ring-blue-200'
                : !step1Done
                  ? 'opacity-60'
                  : ''
            }
          >
            <CardHeader>
              <StepHeader
                label={t('pages.oauthPlayground.stepLabel', {
                  step: 2,
                  title: t('pages.oauthPlayground.step2.title'),
                })}
                description={t('pages.oauthPlayground.step2.desc')}
                completed={step2Done}
                active={currentStep === 2}
                icon={ShieldCheck}
              />
            </CardHeader>
            <CardContent className="space-y-3">
              {session && (
                <>
                  <div className="space-y-1">
                    <label className="text-sm font-medium">{t('pages.oauthPlayground.step2.authorizeUrl')}</label>
                    <div className="flex gap-1">
                      <code className="flex-1 bg-muted p-2 rounded text-xs font-mono break-all max-h-20 overflow-y-auto">
                        {authorizeUrl}
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(authorizeUrl)}
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    onClick={() => window.open(authorizeUrl, '_blank')}
                  >
                    <ExternalLink className="mr-2 h-4 w-4" />
                    {t('pages.oauthPlayground.step2.openInNewTab')}
                  </Button>
                  <div className="space-y-1">
                    <label className="text-sm font-medium">{t('pages.oauthPlayground.step2.authorizationCode')}</label>
                    <div className="flex gap-2">
                      <Input
                        placeholder={t('pages.oauthPlayground.step2.codePlaceholder')}
                        value={authCode}
                        onChange={(e) => setAuthCode(e.target.value)}
                      />
                    </div>
                  </div>
                </>
              )}
              {!session && (
                <p className="text-sm text-muted-foreground">
                  {t('pages.oauthPlayground.step2.blocked')}
                </p>
              )}
            </CardContent>
          </Card>

          {/* Step 3: Exchange Token */}
          <Card
            className={
              currentStep === 3
                ? 'ring-2 ring-blue-200'
                : !step2Done
                  ? 'opacity-60'
                  : ''
            }
          >
            <CardHeader>
              <StepHeader
                label={t('pages.oauthPlayground.stepLabel', {
                  step: 3,
                  title: t('pages.oauthPlayground.step3.title'),
                })}
                description={t('pages.oauthPlayground.step3.desc')}
                completed={step3Done}
                active={currentStep === 3}
                icon={ArrowRightLeft}
              />
            </CardHeader>
            <CardContent className="space-y-3">
              {step2Done && (
                <>
                  <Button
                    onClick={() => exchangeTokenMutation.mutate()}
                    disabled={exchangeTokenMutation.isPending || !authCode.trim()}
                  >
                    {exchangeTokenMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <ArrowRightLeft className="mr-2 h-4 w-4" />
                    )}
                    {t('pages.oauthPlayground.step3.exchange')}
                  </Button>
                  {tokenData && (
                    <div className="space-y-2 text-xs">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <label className="text-sm font-medium">access_token</label>
                          <Badge variant="secondary">
                            {t('pages.oauthPlayground.step3.tokenBadge', {
                              type: tokenData.token_type,
                              n: tokenData.expires_in,
                            })}
                          </Badge>
                        </div>
                        <div className="flex gap-1">
                          <code className="flex-1 bg-muted p-2 rounded font-mono break-all max-h-20 overflow-y-auto">
                            {tokenData.access_token}
                          </code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(tokenData.access_token)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                      {tokenData.id_token && (
                        <div className="space-y-1">
                          <label className="text-sm font-medium">id_token</label>
                          <div className="flex gap-1">
                            <code className="flex-1 bg-muted p-2 rounded font-mono break-all max-h-20 overflow-y-auto">
                              {tokenData.id_token}
                            </code>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(tokenData.id_token)}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                      )}
                      {tokenData.refresh_token && (
                        <div className="space-y-1">
                          <label className="text-sm font-medium">refresh_token</label>
                          <div className="flex gap-1">
                            <code className="flex-1 bg-muted p-2 rounded font-mono break-all max-h-20 overflow-y-auto">
                              {tokenData.refresh_token}
                            </code>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(tokenData.refresh_token!)}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
              {!step2Done && (
                <p className="text-sm text-muted-foreground">
                  {t('pages.oauthPlayground.step3.blocked')}
                </p>
              )}
            </CardContent>
          </Card>

          {/* Step 4: UserInfo */}
          <Card
            className={
              currentStep === 4
                ? 'ring-2 ring-blue-200'
                : !step3Done
                  ? 'opacity-60'
                  : ''
            }
          >
            <CardHeader>
              <StepHeader
                label={t('pages.oauthPlayground.stepLabel', {
                  step: 4,
                  title: t('pages.oauthPlayground.step4.title'),
                })}
                description={t('pages.oauthPlayground.step4.desc')}
                completed={step4Done}
                active={currentStep === 4}
                icon={User}
              />
            </CardHeader>
            <CardContent className="space-y-3">
              {step3Done && (
                <>
                  <Button
                    onClick={() => userInfoMutation.mutate()}
                    disabled={userInfoMutation.isPending}
                  >
                    {userInfoMutation.isPending ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <User className="mr-2 h-4 w-4" />
                    )}
                    {t('pages.oauthPlayground.step4.call')}
                  </Button>
                  {userInfo && (
                    <pre className="text-xs bg-muted rounded p-3 overflow-x-auto">
                      {formatJSON(userInfo)}
                    </pre>
                  )}
                </>
              )}
              {!step3Done && (
                <p className="text-sm text-muted-foreground">
                  {t('pages.oauthPlayground.step4.blocked')}
                </p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right: JWT decoder */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('pages.oauthPlayground.jwt.title')}</CardTitle>
              <CardDescription>{t('pages.oauthPlayground.jwt.desc')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Textarea
                className="font-mono text-xs min-h-[100px]"
                placeholder={t('pages.oauthPlayground.jwt.placeholder')}
                value={jwtInput}
                onChange={(e) => setJwtInput(e.target.value)}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={handleDecodeJWT}
                disabled={!jwtInput.trim()}
              >
                {t('pages.oauthPlayground.jwt.decode')}
              </Button>

              {/* Quick-fill buttons from flow tokens */}
              {tokenData && (
                <div className="flex flex-wrap gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs"
                    onClick={() => {
                      setJwtInput(tokenData.access_token)
                      const result = decodeJWT(tokenData.access_token)
                      if (result) setDecodedJwt(result)
                    }}
                  >
                    {t('pages.oauthPlayground.jwt.useAccessToken')}
                  </Button>
                  {tokenData.id_token && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-xs"
                      onClick={() => {
                        setJwtInput(tokenData.id_token)
                        const result = decodeJWT(tokenData.id_token)
                        if (result) setDecodedJwt(result)
                      }}
                    >
                      {t('pages.oauthPlayground.jwt.useIdToken')}
                    </Button>
                  )}
                </div>
              )}

              {decodedJwt && (
                <Tabs defaultValue="payload">
                  <TabsList className="w-full">
                    <TabsTrigger value="header" className="flex-1 text-xs">
                      {t('pages.oauthPlayground.jwt.header')}
                    </TabsTrigger>
                    <TabsTrigger value="payload" className="flex-1 text-xs">
                      {t('pages.oauthPlayground.jwt.payload')}
                    </TabsTrigger>
                  </TabsList>
                  <TabsContent value="header">
                    <pre className="text-xs bg-muted rounded p-3 overflow-x-auto">
                      {formatJSON(decodedJwt.header)}
                    </pre>
                  </TabsContent>
                  <TabsContent value="payload">
                    <pre className="text-xs bg-muted rounded p-3 overflow-x-auto">
                      {formatJSON(decodedJwt.payload)}
                    </pre>
                    {decodedJwt.expires_at && (
                      <p className="text-xs text-muted-foreground mt-2">
                        {t('pages.oauthPlayground.jwt.expiresAt', { date: decodedJwt.expires_at })}
                      </p>
                    )}
                  </TabsContent>
                </Tabs>
              )}
            </CardContent>
          </Card>

          {/* Flow progress indicator */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t('pages.oauthPlayground.progress.title')}</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {[
                  { label: t('pages.oauthPlayground.step1.title'), done: step1Done },
                  { label: t('pages.oauthPlayground.step2.title'), done: step2Done },
                  { label: t('pages.oauthPlayground.step3.title'), done: step3Done },
                  { label: t('pages.oauthPlayground.step4.title'), done: step4Done },
                ].map((s, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm">
                    {s.done ? (
                      <CheckCircle2 className="h-4 w-4 text-green-600" />
                    ) : (
                      <Circle className="h-4 w-4 text-muted-foreground" />
                    )}
                    <span className={s.done ? 'text-green-700 font-medium' : 'text-muted-foreground'}>
                      {s.label}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
