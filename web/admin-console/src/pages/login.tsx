import { useEffect, useState, useRef, useCallback } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Shield, AlertCircle, Loader2, Globe, ArrowLeft, KeyRound, Smartphone, Mail, Phone, Check, Bell } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Checkbox } from '../components/ui/checkbox'
import { useAuth } from '../lib/auth'
import { api, baseURL, IdentityProvider } from '../lib/api'
import { getProviderIcon } from '../components/icons/social-providers'
import { decodeCredentialRequestOptions, serializeAssertionResponse, type PublicKeyCredentialRequestOptionsJSON } from '../lib/webauthn'
import { QRCodeSVG } from 'qrcode.react'
import { LanguageSwitcher } from '../components/language-switcher'
import { AuthCardFooter, PoweredBy } from '../components/auth-card-footer'

interface MFAOption {
  method: string
  label: string
  icon: React.ReactNode
}

export function LoginPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const { login, isAuthenticated, isLoading } = useAuth()
  const [error, setError] = useState('')
  const [identityProviders, setIdentityProviders] = useState<IdentityProvider[]>([])
  const [loadingIdPs, setLoadingIdPs] = useState(true)

  // Login form state
  const [loginSession, setLoginSession] = useState<string | null>(null)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  // MFA state
  const [mfaRequired, setMfaRequired] = useState(false)
  const [mfaSession, setMfaSession] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [mfaMethods, setMfaMethods] = useState<string[]>([])
  const [selectedMfaMethod, setSelectedMfaMethod] = useState<string>('')
  const [mfaMethodSelectionStep, setMfaMethodSelectionStep] = useState(false)
  const [otpSent, setOtpSent] = useState(false)
  const mfaInputRef = useRef<HTMLInputElement>(null)

  // WebAuthn state
  const [webauthnLoading, setWebauthnLoading] = useState(false)

  // Push MFA state
  const [pushLoading, setPushLoading] = useState(false)
  const [, setPushChallengeId] = useState('')
  const [pushChallengeCode, setPushChallengeCode] = useState('')
  const pushPollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Trust browser state. The decision is made ON the MFA screen and travels
  // with the verification (`trust_browser`), because that is the only request
  // the server can act on: it trusts the browser server-side while it still
  // holds the MFA session. A ref mirrors the checkbox so the in-flight push /
  // WebAuthn closures read the current value instead of a stale capture.
  const [trustBrowser, setTrustBrowser] = useState(false)
  const [canTrustBrowser, setCanTrustBrowser] = useState(false)
  const trustBrowserRef = useRef(false)
  const setTrustBrowserChoice = (value: boolean) => {
    trustBrowserRef.current = value
    setTrustBrowser(value)
  }

  // Concurrent session state
  const [concurrentLimitReached, setConcurrentLimitReached] = useState(false)
  const [activeSessions, setActiveSessions] = useState<any[]>([])
  const [pendingLoginSession, setPendingLoginSession] = useState('')

  // Passkey state
  const [passkeySupported, setPasskeySupported] = useState(false)
  const [passkeyLoading, setPasskeyLoading] = useState(false)

  // Magic link state
  const [showMagicLink, setShowMagicLink] = useState(false)
  const [magicLinkEmail, setMagicLinkEmail] = useState('')
  const [magicLinkSent, setMagicLinkSent] = useState(false)
  const [magicLinkLoading, setMagicLinkLoading] = useState(false)

  // QR login state
  const [showQRLogin, setShowQRLogin] = useState(false)
  const [qrSession, setQrSession] = useState<{ session_token: string; qr_content: string; expires_at: string } | null>(null)
  const [qrLoading, setQrLoading] = useState(false)
  const qrPollingRef2 = useRef<ReturnType<typeof setInterval> | null>(null)

  // Tenant branding state
  const [branding, setBranding] = useState<{
    logo_url?: string
    favicon_url?: string
    primary_color?: string
    secondary_color?: string
    background_color?: string
    background_image_url?: string
    login_page_title?: string
    login_page_message?: string
    portal_title?: string
    custom_css?: string
    custom_footer?: string
    powered_by_visible?: boolean
  }>({})

  // Fetch tenant branding based on domain
  useEffect(() => {
    const domain = window.location.hostname
    if (domain && domain !== 'localhost') {
      api.get<Record<string, unknown>>(`/api/v1/identity/branding?domain=${domain}`)
        .then(data => { if (data) setBranding(data as typeof branding) })
        .catch(() => {})
    }
  }, [])

  // Apply tenant branding to the document (favicon, custom CSS, page background,
  // document title). These are document-level side effects, so we apply/clean
  // them up here rather than threading them through every login sub-screen's JSX.
  useEffect(() => {
    const cleanups: Array<() => void> = []

    // Favicon
    if (branding.favicon_url) {
      let link = document.querySelector<HTMLLinkElement>("link[rel~='icon']")
      const created = !link
      if (!link) {
        link = document.createElement('link')
        link.rel = 'icon'
        document.head.appendChild(link)
      }
      const prevHref = link.href
      link.href = branding.favicon_url
      cleanups.push(() => {
        if (created) link?.remove()
        else if (link) link.href = prevHref
      })
    }

    // Document title from portal title
    if (branding.portal_title) {
      const prevTitle = document.title
      document.title = branding.portal_title
      cleanups.push(() => { document.title = prevTitle })
    }

    // Tenant-supplied custom CSS (trusted admin input, same trust level as the
    // admin Branding page). Injected as a dedicated <style> element.
    if (branding.custom_css) {
      const style = document.createElement('style')
      style.setAttribute('data-tenant-branding', 'true')
      style.textContent = branding.custom_css
      document.head.appendChild(style)
      cleanups.push(() => { style.remove() })
    }

    // Page background (color + optional image). Applied to <body> so it covers
    // every login screen variant uniformly.
    const body = document.body
    const prevBg = body.style.background
    const prevBgColor = body.style.backgroundColor
    if (branding.background_image_url) {
      body.style.background = `url("${branding.background_image_url}") center / cover no-repeat fixed`
      if (branding.background_color) body.style.backgroundColor = branding.background_color
      cleanups.push(() => { body.style.background = prevBg; body.style.backgroundColor = prevBgColor })
    } else if (branding.background_color) {
      body.style.backgroundColor = branding.background_color
      cleanups.push(() => { body.style.backgroundColor = prevBgColor })
    }

    return () => { cleanups.forEach(fn => fn()) }
  }, [branding.favicon_url, branding.portal_title, branding.custom_css, branding.background_image_url, branding.background_color])

  // Branded header pieces shared across the login sub-screens. When the tenant
  // sets a primary (and optional secondary) color we recolor the gradient title;
  // a tenant logo replaces the default Shield badge.
  const brandTitleStyle = branding.primary_color
    ? { backgroundImage: `linear-gradient(to right, ${branding.primary_color}, ${branding.secondary_color || branding.primary_color})` }
    : undefined
  const renderBrandLogo = () =>
    branding.logo_url ? (
      <img src={branding.logo_url} alt="" className="h-16 w-auto max-w-[12rem] object-contain mx-auto" />
    ) : (
      <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
        <Shield className="h-9 w-9 text-white" />
      </div>
    )

  // Check if passkeys/WebAuthn are supported
  useEffect(() => {
    if (window.PublicKeyCredential) {
      setPasskeySupported(true)
    }
  }, [])

  // Check for login_session parameter on mount.
  //
  // login_session ties this login to a pending OIDC /oauth/authorize request
  // (SecureTask and other external clients). It MUST survive:
  //   - the URL being cleaned (replaceState below),
  //   - a component remount,
  //   - the user pressing Back/Cancel from the MFA screen.
  // Keeping it only in React state (and wiping the URL) lost it on any of those,
  // so the next login submitted login_session:null and the pending OAuth request
  // silently degraded into a normal console login -> /dashboard, with no code
  // ever returned to the client. Persist it in sessionStorage as the source of
  // truth for the lifetime of the pending authorization.
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const fromUrl = urlParams.get('login_session')
    const session = fromUrl || sessionStorage.getItem('oidc_login_session')
    if (session) {
      sessionStorage.setItem('oidc_login_session', session)
      setLoginSession(session)
    }
    if (fromUrl) {
      // Clear the URL parameter without reloading (value now lives in storage).
      window.history.replaceState({}, '', '/login')
    }
  }, [])

  // If already authenticated, redirect to dashboard — UNLESS there is a pending
  // OIDC authorization (login_session). The server's /oauth/authorize always
  // routes through this login page to mint the authorization code (there is no
  // cookie-based SSO short-circuit server-side), so an already-logged-in console
  // user must still complete the pending request here instead of being bounced
  // to /dashboard, which would strand every external client login.
  useEffect(() => {
    const pendingOIDC = loginSession || sessionStorage.getItem('oidc_login_session')
    if (isAuthenticated && !pendingOIDC) {
      navigate('/dashboard', { replace: true })
    }
  }, [isAuthenticated, navigate, loginSession])

  // Fetch Identity Providers
  useEffect(() => {
    const fetchIdPs = async () => {
      try {
        setLoadingIdPs(true)
        const data = await api.getIdentityProviders()
        setIdentityProviders(data.filter(idp => idp.enabled)) // Only show enabled IdPs
      } catch (err) {
        // Silent failure - IdPs are optional
        console.error("Failed to fetch identity providers:", err);
      } finally {
        setLoadingIdPs(false)
      }
    }
    fetchIdPs()
  }, [])

  // Check for OAuth callback parameters and handle authentication
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const hasOAuthParams = urlParams.has('code') || urlParams.has('state') || urlParams.has('session_state')

    if (hasOAuthParams && !isLoading) {
      // OAuth callback - the auth provider will handle this
      const timer = setTimeout(() => {
        if (!isAuthenticated) {
          setError(t('login.errors.authFailed'))
        }
      }, 3000)

      return () => clearTimeout(timer)
    }
  }, [isAuthenticated, isLoading])

  const handleLogin = async () => {
    setError('')
    login()
  }

  // completeOIDCRedirect finalizes a pending OIDC authorization: the pending
  // login_session has now been exchanged for an authorization code embedded in
  // `url`, so clear the durable session marker and hand off to the client's
  // redirect_uri. Use this everywhere a redirect_url is returned so we never
  // leave a stale login_session behind to interfere with the next login.
  const completeOIDCRedirect = (url: string) => {
    try {
      sessionStorage.removeItem('oidc_login_session')
    } catch {
      // sessionStorage may be unavailable (private mode); non-fatal.
    }
    window.location.href = url
  }

  const handleSSOLogin = (idp: IdentityProvider) => {
    setError('')
    const redirectUrl = `${baseURL}/oauth/authorize?response_type=code&client_id=admin-console&redirect_uri=${window.location.origin}/login&scope=openid%20profile%20email&idp_hint=${idp.id}`
    window.location.href = redirectUrl
  }

  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSubmitting(true)

    try {
      const response = await fetch(`${baseURL}/oauth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          password,
          login_session: loginSession,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.error_description || t('login.errors.loginFailed'))
        return
      }

      // Check if concurrent session limit reached
      if (data.concurrent_limit_reached) {
        setConcurrentLimitReached(true)
        setActiveSessions(data.active_sessions || [])
        setPendingLoginSession(data.login_session)
        return
      }

      // Check if MFA is required
      if (data.mfa_required) {
        setMfaRequired(true)
        setMfaSession(data.mfa_session)
        setMfaCode('')
        setError('')
        // Offer "trust this browser" only when the server says this browser
        // isn't trusted yet; the choice is sent with the verification below.
        setCanTrustBrowser(!!data.can_trust_browser)
        setTrustBrowserChoice(false)

        // Check if multiple MFA methods are available
        const methods = data.mfa_methods || ['totp']
        setMfaMethods(methods)

        if (methods.length > 1) {
          // Show method selection
          setMfaMethodSelectionStep(true)
        } else {
          // Single method - proceed directly
          setSelectedMfaMethod(methods[0])
          if (methods[0] === 'sms' || methods[0] === 'email') {
            sendOTP(data.mfa_session, methods[0])
          } else if (methods[0] === 'webauthn') {
            beginWebAuthnChallenge(data.mfa_session)
          } else if (methods[0] === 'push') {
            beginPushChallenge(data.mfa_session)
          } else {
            setTimeout(() => mfaInputRef.current?.focus(), 100)
          }
        }
        return
      }

      // Redirect to the URL with the authorization code
      if (data.redirect_url) {
        completeOIDCRedirect(data.redirect_url)
      }
    } catch (err) {
      setError(t('login.errors.network'))
      console.error('Login error:', err)
    } finally {
      setIsSubmitting(false)
    }
  }

  // Send OTP for SMS/Email methods
  const sendOTP = async (session: string, method: string) => {
    try {
      const response = await fetch(`${baseURL}/oauth/mfa-send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfa_session: session,
          method: method,
        }),
      })

      if (response.ok) {
        setOtpSent(true)
        setTimeout(() => mfaInputRef.current?.focus(), 100)
      } else {
        const data = await response.json()
        setError(data.error_description || t('login.errors.otpSendFailed'))
      }
    } catch (err) {
      setError(t('login.errors.otpSendNetwork'))
    }
  }

  // Begin WebAuthn authentication ceremony
  const beginWebAuthnChallenge = useCallback(async (session: string) => {
    setWebauthnLoading(true)
    setError('')

    try {
      // Step 1: Get WebAuthn options from server
      const response = await fetch(`${baseURL}/oauth/mfa-webauthn-begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfa_session: session }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error_description || t('login.errors.webauthnStart'))
      }

      const serverOptions = await response.json()

      // Step 2: Decode options and call browser WebAuthn API
      const publicKeyOptions = serverOptions.publicKey || serverOptions
      const options = decodeCredentialRequestOptions(publicKeyOptions as PublicKeyCredentialRequestOptionsJSON)
      const credential = await navigator.credentials.get({ publicKey: options }) as PublicKeyCredential

      if (!credential) {
        throw new Error(t('login.errors.webauthnCancelled'))
      }

      // Step 3: Serialize and send to mfa-verify
      const assertionJSON = serializeAssertionResponse(credential)

      const verifyResponse = await fetch(`${baseURL}/oauth/mfa-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfa_session: session,
          code: assertionJSON,
          method: 'webauthn',
          trust_browser: trustBrowserRef.current,
        }),
      })

      const verifyData = await verifyResponse.json()

      if (!verifyResponse.ok) {
        throw new Error(verifyData.error_description || t('login.errors.webauthnVerify'))
      }

      if (verifyData.redirect_url) {
        completeOIDCRedirect(verifyData.redirect_url)
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : t('login.errors.webauthnFailed')
      setError(message)
      setWebauthnLoading(false)
    }
  }, [])

  // Begin Push MFA challenge with polling
  const beginPushChallenge = useCallback(async (session: string) => {
    setPushLoading(true)
    setError('')

    try {
      // Step 1: Create push challenge
      const response = await fetch(`${baseURL}/oauth/mfa-push-begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfa_session: session }),
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error_description || t('login.errors.pushStart'))
      }

      const data = await response.json()
      setPushChallengeId(data.challenge_id)
      setPushChallengeCode(data.challenge_code)

      // Step 2: Start polling for approval
      const pollInterval = setInterval(async () => {
        try {
          const statusResponse = await fetch(`${baseURL}/oauth/mfa-push-status/${data.challenge_id}`)
          const statusData = await statusResponse.json()

          if (statusData.status === 'approved') {
            clearInterval(pollInterval)
            pushPollingRef.current = null

            // Step 3: Complete MFA verify with challenge_id
            const verifyResponse = await fetch(`${baseURL}/oauth/mfa-verify`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                mfa_session: session,
                code: data.challenge_id,
                method: 'push',
                trust_browser: trustBrowserRef.current,
              }),
            })

            const verifyData = await verifyResponse.json()

            if (!verifyResponse.ok) {
              setError(verifyData.error_description || t('login.errors.pushVerify'))
              setPushLoading(false)
              return
            }

            if (verifyData.redirect_url) {
              completeOIDCRedirect(verifyData.redirect_url)
            }
          } else if (statusData.status === 'denied') {
            clearInterval(pollInterval)
            pushPollingRef.current = null
            setError(t('login.errors.pushDenied'))
            setPushLoading(false)
          } else if (statusData.status === 'expired') {
            clearInterval(pollInterval)
            pushPollingRef.current = null
            setError(t('login.errors.pushExpired'))
            setPushLoading(false)
          }
        } catch {
          // Network error during polling — continue polling
        }
      }, 2000)

      pushPollingRef.current = pollInterval
    } catch (err) {
      const message = err instanceof Error ? err.message : t('login.errors.pushInit')
      setError(message)
      setPushLoading(false)
    }
  }, [])

  // Cleanup push polling and QR polling on unmount
  useEffect(() => {
    return () => {
      if (pushPollingRef.current) {
        clearInterval(pushPollingRef.current)
      }
      if (qrPollingRef2.current) {
        clearInterval(qrPollingRef2.current)
      }
    }
  }, [])

  // Select MFA method when multiple are available
  const selectMfaMethod = (method: string) => {
    setSelectedMfaMethod(method)
    setMfaMethodSelectionStep(false)
    setMfaCode('')

    // Stop any existing push polling
    if (pushPollingRef.current) {
      clearInterval(pushPollingRef.current)
      pushPollingRef.current = null
    }
    setPushLoading(false)
    setWebauthnLoading(false)

    if (method === 'sms' || method === 'email') {
      sendOTP(mfaSession, method)
    } else if (method === 'webauthn') {
      beginWebAuthnChallenge(mfaSession)
    } else if (method === 'push') {
      beginPushChallenge(mfaSession)
    } else {
      setTimeout(() => mfaInputRef.current?.focus(), 100)
    }
  }

  const handleMFASubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsSubmitting(true)

    try {
      const response = await fetch(`${baseURL}/oauth/mfa-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mfa_session: mfaSession,
          code: mfaCode,
          method: selectedMfaMethod || 'totp',
          trust_browser: trustBrowserRef.current,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.error_description || t('login.errors.invalidCode'))
        setMfaCode('')
        mfaInputRef.current?.focus()
        return
      }

      if (data.redirect_url) {
        completeOIDCRedirect(data.redirect_url)
      }
    } catch (err) {
      setError(t('login.errors.network'))
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleBackToOptions = () => {
    // Clean up push polling
    if (pushPollingRef.current) {
      clearInterval(pushPollingRef.current)
      pushPollingRef.current = null
    }

    // NOTE: intentionally do NOT clear loginSession here. "Back to login" /
    // "Cancel" returns the user to the credentials form for the SAME pending
    // OIDC request; wiping login_session made the next submit degrade into a
    // plain console login and stranded the external client.
    setMfaRequired(false)
    setMfaSession('')
    setMfaCode('')
    setMfaMethods([])
    setSelectedMfaMethod('')
    setMfaMethodSelectionStep(false)
    setOtpSent(false)
    setWebauthnLoading(false)
    setPushLoading(false)
    setPushChallengeId('')
    setPushChallengeCode('')
    setUsername('')
    setPassword('')
    setError('')
    setTrustBrowserChoice(false)
    setCanTrustBrowser(false)
  }

  const handleForceLogin = async (terminateSessionId: string) => {
    try {
      const response = await fetch(`${baseURL}/oauth/force-login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          terminate_session_id: terminateSessionId,
          login_session: pendingLoginSession,
        }),
      })
      const data = await response.json()
      if (data.redirect_url) {
        completeOIDCRedirect(data.redirect_url)
      } else {
        setError(data.error_description || t('login.errors.forceLogin'))
      }
    } catch (err) {
      setError(t('login.errors.forceLogin'))
    }
    setConcurrentLimitReached(false)
  }

  const getMfaMethodInfo = (method: string): MFAOption => {
    switch (method) {
      case 'totp':
        return { method: 'totp', label: t('login.mfa.totp.label'), icon: <Smartphone className="h-5 w-5" /> }
      case 'sms':
        return { method: 'sms', label: t('login.mfa.sms.label'), icon: <Phone className="h-5 w-5" /> }
      case 'email':
        return { method: 'email', label: t('login.mfa.email.label'), icon: <Mail className="h-5 w-5" /> }
      case 'webauthn':
        return { method: 'webauthn', label: t('login.mfa.webauthn.label'), icon: <KeyRound className="h-5 w-5" /> }
      case 'push':
        return { method: 'push', label: t('login.mfa.push.label'), icon: <Bell className="h-5 w-5" /> }
      default:
        return { method, label: method.toUpperCase(), icon: <Shield className="h-5 w-5" /> }
    }
  }

  const handlePasskeyLogin = async () => {
    if (!loginSession) return
    setPasskeyLoading(true)
    setError('')

    try {
      const beginResp = await fetch(`${baseURL}/oauth/passkey-begin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login_session: loginSession }),
      })
      if (!beginResp.ok) {
        const d = await beginResp.json()
        throw new Error(d.error_description || t('login.errors.passkeyNone'))
      }
      const serverOptions = await beginResp.json()

      const publicKeyOptions = serverOptions.publicKey || serverOptions
      const options = decodeCredentialRequestOptions(publicKeyOptions as PublicKeyCredentialRequestOptionsJSON)
      const credential = await navigator.credentials.get({ publicKey: options }) as PublicKeyCredential
      if (!credential) throw new Error(t('login.errors.passkeyCancelled'))

      const assertionJSON = serializeAssertionResponse(credential)
      const finishResp = await fetch(`${baseURL}/oauth/passkey-finish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          login_session: loginSession,
          credential: JSON.parse(assertionJSON),
        }),
      })
      const finishData = await finishResp.json()
      if (!finishResp.ok) throw new Error(finishData.error_description || t('login.errors.passkeyVerify'))
      if (finishData.redirect_url) completeOIDCRedirect(finishData.redirect_url)
    } catch (err) {
      const msg = err instanceof Error ? err.message : t('login.errors.passkeyFailed')
      setError(msg)
    } finally {
      setPasskeyLoading(false)
    }
  }

  // Passwordless phone sign-in: no password — prove identity by approving a
  // push on your registered device. Requires a username and a pending OIDC
  // login_session; the server only proceeds if the user has an enabled push
  // device, then we run the existing push challenge flow.
  const handlePhoneSignIn = async () => {
    if (!loginSession) return
    if (!username.trim()) {
      setError(t('login.errors.phoneNeedsUsername'))
      return
    }
    setPushLoading(true)
    setError('')
    try {
      const resp = await fetch(`${baseURL}/oauth/passwordless/phone/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), login_session: loginSession }),
      })
      const data = await resp.json()
      if (!resp.ok) {
        setError(data.error_description || t('login.errors.phoneUnavailable'))
        setPushLoading(false)
        return
      }
      // Enter the MFA (push) step and start the challenge — same flow the
      // password path uses once a push factor is selected.
      setMfaRequired(true)
      setMfaSession(data.mfa_session)
      setSelectedMfaMethod('push')
      beginPushChallenge(data.mfa_session)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('login.errors.passwordlessFailed'))
      setPushLoading(false)
    }
  }

  const handleMagicLinkRequest = async () => {
    if (!loginSession || !magicLinkEmail) return
    setMagicLinkLoading(true)
    setError('')
    try {
      await fetch(`${baseURL}/oauth/magic-link`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: magicLinkEmail, login_session: loginSession }),
      })
      setMagicLinkSent(true)
    } catch {
      setError(t('login.errors.magicLinkFailed'))
    } finally {
      setMagicLinkLoading(false)
    }
  }

  const initQRLogin = async () => {
    if (!loginSession) return
    setQrLoading(true)
    setShowQRLogin(true)
    setError('')

    try {
      const resp = await fetch(`${baseURL}/oauth/qr-login/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login_session: loginSession }),
      })
      if (!resp.ok) throw new Error('Failed to create QR session')
      const data = await resp.json()
      setQrSession(data)

      // Start polling
      if (qrPollingRef2.current) clearInterval(qrPollingRef2.current)
      qrPollingRef2.current = setInterval(async () => {
        try {
          const pollResp = await fetch(`${baseURL}/oauth/qr-login/poll?session_token=${data.session_token}&login_session=${loginSession}`)
          const pollData = await pollResp.json()
          if (pollData.redirect_url) {
            if (qrPollingRef2.current) clearInterval(qrPollingRef2.current)
            completeOIDCRedirect(pollData.redirect_url)
          } else if (pollData.status === 'expired') {
            if (qrPollingRef2.current) clearInterval(qrPollingRef2.current)
            setQrSession(null)
            setShowQRLogin(false)
            setError(t('login.errors.qrExpired'))
          }
        } catch { /* ignore polling errors */ }
      }, 2000)
    } catch {
      setError(t('login.errors.qrCreateFailed'))
      setShowQRLogin(false)
    } finally {
      setQrLoading(false)
    }
  }

  // Show MFA method selection
  if (mfaRequired && loginSession && mfaMethodSelectionStep) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <div className="absolute top-4 right-4">
          <LanguageSwitcher />
        </div>
        <Card className="w-full max-w-md shadow-xl">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
                <Shield className="h-9 w-9 text-white" />
              </div>
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">
                {t('login.mfa.chooseTitle')}
              </CardTitle>
              <CardDescription className="text-base mt-2">
                {t('login.mfa.chooseSubtitle')}
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent className="space-y-3">
            {error && (
              <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
                <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
                <p className="text-sm text-red-600">{error}</p>
              </div>
            )}

            {mfaMethods.map((method) => {
              const info = getMfaMethodInfo(method)
              return (
                <Button
                  key={method}
                  variant="outline"
                  className="w-full h-auto py-4 justify-start"
                  onClick={() => selectMfaMethod(method)}
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 rounded-lg text-primary">
                      {info.icon}
                    </div>
                    <div className="text-left">
                      <p className="font-medium">{info.label}</p>
                      <p className="text-xs text-muted-foreground">
                        {method === 'totp' && t('login.mfa.totp.hint')}
                        {method === 'sms' && t('login.mfa.sms.hint')}
                        {method === 'email' && t('login.mfa.email.hint')}
                        {method === 'webauthn' && t('login.mfa.webauthn.hint')}
                        {method === 'push' && t('login.mfa.push.hint')}
                      </p>
                    </div>
                  </div>
                </Button>
              )
            })}

            <Button
              type="button"
              variant="ghost"
              className="w-full mt-4"
              onClick={handleBackToOptions}
            >
              <ArrowLeft className="mr-2 h-4 w-4" />
              {t('login.mfa.backToLogin')}
            </Button>
          </CardContent>

          <AuthCardFooter />
        </Card>
      </div>
    )
  }

  // Show MFA verification form
  if (mfaRequired && loginSession) {
    const methodInfo = getMfaMethodInfo(selectedMfaMethod || 'totp')
    const isWebAuthn = selectedMfaMethod === 'webauthn'
    const isPush = selectedMfaMethod === 'push'

    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <div className="absolute top-4 right-4">
          <LanguageSwitcher />
        </div>
        <Card className="w-full max-w-md shadow-xl">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
                {methodInfo.icon ? (
                  <div className="text-white [&>svg]:h-9 [&>svg]:w-9">{methodInfo.icon}</div>
                ) : (
                  <KeyRound className="h-9 w-9 text-white" />
                )}
              </div>
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">
                {methodInfo.label}
              </CardTitle>
              <CardDescription className="text-base mt-2">
                {selectedMfaMethod === 'totp' && t('login.mfa.totp.prompt')}
                {selectedMfaMethod === 'sms' && (otpSent ? t('login.mfa.sms.promptSent') : t('login.mfa.sms.promptSending'))}
                {selectedMfaMethod === 'email' && (otpSent ? t('login.mfa.email.promptSent') : t('login.mfa.email.promptSending'))}
                {isWebAuthn && t('login.mfa.webauthn.prompt')}
                {isPush && t('login.mfa.push.prompt')}
                {!selectedMfaMethod && t('login.mfa.totp.prompt')}
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent>
            {error && (
              <div className="flex items-center gap-2 p-3 mb-4 bg-red-50 border border-red-200 rounded-md">
                <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
                <p className="text-sm text-red-600">{error}</p>
              </div>
            )}

            {/* Trust this browser: sent WITH the verification below, which is
                what actually records the trust server-side (and lets adaptive
                MFA skip the challenge next time on this device). */}
            {canTrustBrowser && (
              <div className="flex items-start gap-3 mb-4 rounded-md border border-border bg-muted/50 p-3">
                <Checkbox
                  id="trust-browser"
                  checked={trustBrowser}
                  onCheckedChange={(checked) => setTrustBrowserChoice(checked === true)}
                  className="mt-0.5"
                />
                <Label htmlFor="trust-browser" className="text-sm font-normal leading-snug cursor-pointer">
                  {t('login.mfa.trustBrowser')}
                  <span className="block text-xs text-muted-foreground">
                    {t('login.mfa.trustBrowserHint')}
                  </span>
                </Label>
              </div>
            )}

            {/* WebAuthn: Waiting for security key */}
            {isWebAuthn && (
              <div className="space-y-4">
                {webauthnLoading ? (
                  <div className="text-center py-6">
                    <Loader2 className="h-10 w-10 animate-spin mx-auto text-primary mb-4" />
                    <p className="text-lg font-medium">{t('login.mfa.webauthn.waiting')}</p>
                    <p className="text-sm text-muted-foreground mt-2">
                      {t('login.mfa.webauthn.waitingHint')}
                    </p>
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <KeyRound className="h-10 w-10 mx-auto text-muted-foreground mb-4" />
                    <Button
                      className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                      size="lg"
                      onClick={() => beginWebAuthnChallenge(mfaSession)}
                    >
                      {t('login.mfa.webauthn.retry')}
                    </Button>
                  </div>
                )}
              </div>
            )}

            {/* Push MFA: Waiting for approval with challenge code */}
            {isPush && (
              <div className="space-y-4">
                {pushLoading ? (
                  <div className="text-center py-6">
                    <Loader2 className="h-10 w-10 animate-spin mx-auto text-green-600 mb-4" />
                    {pushChallengeCode && (
                      <div className="mb-4">
                        <p className="text-sm text-muted-foreground mb-2">{t('login.mfa.push.verifyNumber')}</p>
                        <div className="text-5xl font-bold font-mono tracking-widest text-blue-700">
                          {pushChallengeCode}
                        </div>
                      </div>
                    )}
                    <p className="text-lg font-medium">{t('login.mfa.push.waiting')}</p>
                    <p className="text-sm text-muted-foreground mt-2">
                      {t('login.mfa.push.waitingHint')}
                    </p>
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-4"
                      onClick={() => {
                        if (pushPollingRef.current) {
                          clearInterval(pushPollingRef.current)
                          pushPollingRef.current = null
                        }
                        setPushLoading(false)
                        setError(t('login.errors.pushCancelled'))
                      }}
                    >
                      {t('common.cancel')}
                    </Button>
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <Bell className="h-10 w-10 mx-auto text-muted-foreground mb-4" />
                    <Button
                      className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                      size="lg"
                      onClick={() => beginPushChallenge(mfaSession)}
                    >
                      {t('login.mfa.push.send')}
                    </Button>
                  </div>
                )}
              </div>
            )}

            {/* Standard code input (totp, sms, email, backup, bypass) */}
            {!isWebAuthn && !isPush && (
              <form onSubmit={handleMFASubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="mfa-code">{t('login.mfa.codeLabel')}</Label>
                  <Input
                    ref={mfaInputRef}
                    id="mfa-code"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    placeholder="000000"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    required
                    autoFocus
                    className="text-center text-2xl tracking-widest font-mono"
                  />
                </div>

                {(selectedMfaMethod === 'sms' || selectedMfaMethod === 'email') && (
                  <Button
                    type="button"
                    variant="link"
                    className="w-full text-sm"
                    onClick={() => sendOTP(mfaSession, selectedMfaMethod)}
                    disabled={isSubmitting}
                  >
                    {t('login.mfa.resend')}
                  </Button>
                )}

                <Button
                  type="submit"
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                  size="lg"
                  disabled={isSubmitting || mfaCode.length !== 6}
                >
                  {isSubmitting ? (
                    <span className="flex items-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      {t('login.mfa.verifying')}
                    </span>
                  ) : (
                    t('login.mfa.verify')
                  )}
                </Button>
              </form>
            )}

            <div className="space-y-2 mt-4">
              {mfaMethods.length > 1 && (
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  onClick={() => {
                    if (pushPollingRef.current) {
                      clearInterval(pushPollingRef.current)
                      pushPollingRef.current = null
                    }
                    setPushLoading(false)
                    setWebauthnLoading(false)
                    setMfaMethodSelectionStep(true)
                    setMfaCode('')
                    setOtpSent(false)
                  }}
                >
                  {t('login.mfa.differentMethod')}
                </Button>
              )}

              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={handleBackToOptions}
              >
                <ArrowLeft className="mr-2 h-4 w-4" />
                {t('login.mfa.backToLogin')}
              </Button>
            </div>
          </CardContent>

          <AuthCardFooter />
        </Card>

        <div className="absolute bottom-4 text-center w-full">
          <PoweredBy />
        </div>
      </div>
    )
  }

  // Show login form when login_session is present
  if (loginSession) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <div className="absolute top-4 right-4">
          <LanguageSwitcher />
        </div>
        <Card className="w-full max-w-md shadow-xl">
          <CardHeader className="text-center space-y-4">
            <div className="flex justify-center">
              {renderBrandLogo()}
            </div>
            <div>
              <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent" style={brandTitleStyle}>
                {branding.portal_title || 'OpenIDX'}
              </CardTitle>
              <CardDescription className="text-base mt-2">
                {branding.login_page_message || t('login.form.signInWithCredentials')}
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent>
            {passkeySupported && (
              <div className="mb-4">
                <Button
                  variant="outline"
                  className="w-full gap-2"
                  onClick={handlePasskeyLogin}
                  disabled={passkeyLoading}
                >
                  {passkeyLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                  {t('login.form.passkey')}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="w-full gap-2"
                  onClick={handlePhoneSignIn}
                  disabled={pushLoading}
                >
                  {pushLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Smartphone className="h-4 w-4" />}
                  {t('login.form.phone')}
                </Button>
                <div className="relative my-4">
                  <div className="absolute inset-0 flex items-center"><span className="w-full border-t" /></div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-background px-2 text-muted-foreground">{t('login.form.orPassword')}</span>
                  </div>
                </div>
              </div>
            )}

            <form onSubmit={handleCredentialsSubmit} className="space-y-4">
              {error && (
                <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
                  <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
                  <p className="text-sm text-red-600">{error}</p>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="username">{t('login.form.usernameLabel')}</Label>
                <Input
                  id="username"
                  name="username"
                  type="text"
                  placeholder={t('login.form.usernamePlaceholder')}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoComplete="username"
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">{t('login.form.passwordLabel')}</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  placeholder={t('login.form.passwordPlaceholder')}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                />
              </div>

              <Button
                type="submit"
                className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                size="lg"
                disabled={isSubmitting}
              >
                {isSubmitting ? (
                  <span className="flex items-center gap-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t('login.form.signingIn')}
                  </span>
                ) : (
                  t('login.form.signIn')
                )}
              </Button>

              <div className="text-center">
                <Link to="/forgot-password" className="text-sm text-primary hover:text-blue-800">
                  {t('login.form.forgotPassword')}
                </Link>
              </div>

              <Button
                type="button"
                variant="ghost"
                className="w-full"
                onClick={handleBackToOptions}
              >
                <ArrowLeft className="mr-2 h-4 w-4" />
                {t('login.form.backToOptions')}
              </Button>
            </form>

            {/* Magic Link Option */}
            <div className="mt-4 pt-4 border-t">
              {!showMagicLink && !magicLinkSent && (
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full text-sm text-muted-foreground"
                  onClick={() => setShowMagicLink(true)}
                >
                  <Mail className="mr-2 h-4 w-4" />
                  {t('login.magicLink.request')}
                </Button>
              )}
              {showMagicLink && !magicLinkSent && (
                <div className="space-y-2">
                  <Label htmlFor="magic-email">{t('login.magicLink.emailLabel')}</Label>
                  <div className="flex gap-2">
                    <Input
                      id="magic-email"
                      type="email"
                      placeholder="your@email.com"
                      value={magicLinkEmail}
                      onChange={(e) => setMagicLinkEmail(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleMagicLinkRequest()}
                    />
                    <Button onClick={handleMagicLinkRequest} disabled={magicLinkLoading || !magicLinkEmail}>
                      {magicLinkLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : t('login.magicLink.send')}
                    </Button>
                  </div>
                </div>
              )}
              {magicLinkSent && (
                <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-md">
                  <Check className="h-4 w-4 text-green-600 flex-shrink-0" />
                  <p className="text-sm text-green-700">{t('login.magicLink.sent')}</p>
                </div>
              )}
            </div>

            {/* QR Code Login Option */}
            <div className="mt-2">
              {!showQRLogin && (
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full text-sm text-muted-foreground"
                  onClick={initQRLogin}
                  disabled={qrLoading}
                >
                  <Smartphone className="mr-2 h-4 w-4" />
                  {t('login.qr.signIn')}
                </Button>
              )}
              {showQRLogin && qrSession && (
                <div className="space-y-3 text-center">
                  <p className="text-sm text-muted-foreground">{t('login.qr.scanHint')}</p>
                  <div className="flex justify-center">
                    <QRCodeSVG value={qrSession.qr_content} size={220} level="H" marginSize={4} />
                  </div>
                  <p className="text-xs text-muted-foreground">{t('login.qr.waiting')}</p>
                  <Button variant="ghost" size="sm" onClick={() => { setShowQRLogin(false); setQrSession(null); if (qrPollingRef2.current) clearInterval(qrPollingRef2.current) }}>
                    {t('common.cancel')}
                  </Button>
                </div>
              )}
            </div>
          </CardContent>

          <AuthCardFooter />
        </Card>

        <div className="absolute bottom-4 text-center w-full">
          <PoweredBy />
        </div>
      </div>
    )
  }

  // Show login options (SSO + OpenIDX button)
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <div className="absolute top-4 right-4">
        <LanguageSwitcher />
      </div>
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-4">
          <div className="flex justify-center">
            {renderBrandLogo()}
          </div>
          <div>
            <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent" style={brandTitleStyle}>
              {branding.portal_title || 'OpenIDX'}
            </CardTitle>
            <CardDescription className="text-base mt-2">
              {branding.login_page_message || t('login.options.platformSubtitle')}
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {error && (
            <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
              <AlertCircle className="h-4 w-4 text-red-600 flex-shrink-0" />
              <p className="text-sm text-red-600">{error}</p>
            </div>
          )}

          <div className="space-y-4">
            <p className="text-center text-sm text-muted-foreground">
              {t('login.options.accessHint')}
            </p>

            {loadingIdPs ? (
              <div className="flex justify-center">
                <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
              </div>
            ) : (
              <>
                {identityProviders.map((idp) => {
                  const ProviderIcon = getProviderIcon(idp.issuer_url)
                  return (
                    <Button
                      key={idp.id}
                      onClick={() => handleSSOLogin(idp)}
                      className="w-full bg-gray-700 hover:bg-gray-800 text-white"
                      size="lg"
                      disabled={isLoading}
                    >
                      {ProviderIcon ? <ProviderIcon className="mr-2 h-4 w-4" /> : <Globe className="mr-2 h-4 w-4" />}
                      {t('login.options.ssoWith', { name: idp.name })}
                    </Button>
                  )
                })}

                {identityProviders.length > 0 && <div className="relative my-4">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-card px-2 text-muted-foreground">{t('login.options.orContinueWith')}</span>
                  </div>
                </div>}

                <Button
                  onClick={handleLogin}
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                  size="lg"
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <span className="flex items-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      {t('login.form.signingIn')}
                    </span>
                  ) : (
                    t('login.options.signInOpenidx')
                  )}
                </Button>

                <div className="text-center">
                  <Link to="/forgot-password" className="text-sm text-primary hover:text-blue-800">
                    {t('login.form.forgotPassword')}
                  </Link>
                </div>
              </>
            )}
          </div>

          <div className="text-center">
            <p className="text-xs text-muted-foreground">
              {t('login.options.securedBy')}
            </p>
          </div>
        </CardContent>

        <AuthCardFooter />
      </Card>

      {/* Concurrent Session Limit Dialog */}
      {concurrentLimitReached && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <Card className="w-full max-w-md">
            <CardHeader>
              <CardTitle className="text-lg">{t('login.concurrent.title')}</CardTitle>
              <CardDescription>
                {t('login.concurrent.description')}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {activeSessions.map((session: any) => (
                <div key={session.id} className="flex items-center justify-between rounded-lg border p-3">
                  <div className="text-sm">
                    <div className="font-medium">{session.ip_address}</div>
                    <div className="text-muted-foreground truncate max-w-[200px]">{session.user_agent?.substring(0, 50)}</div>
                    <div className="text-muted-foreground text-xs">{t('login.concurrent.lastActive', { time: new Date(session.last_seen_at).toLocaleString() })}</div>
                  </div>
                  <Button variant="destructive" size="sm" onClick={() => handleForceLogin(session.id)}>
                    {t('login.concurrent.signOut')}
                  </Button>
                </div>
              ))}
              <Button variant="outline" className="w-full" onClick={() => setConcurrentLimitReached(false)}>
                {t('common.cancel')}
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Footer branding */}
      <div className="absolute bottom-4 text-center w-full space-y-1">
        {branding.custom_footer && (
          <p className="text-sm text-muted-foreground">{branding.custom_footer}</p>
        )}
        {branding.powered_by_visible !== false && (
          <PoweredBy />
        )}
      </div>
    </div>
  )
}
