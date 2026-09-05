import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Shield, ArrowLeft, Loader2, CheckCircle, AlertCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { baseURL } from '../lib/api'
import { AuthCardFooter, PoweredBy } from '../components/auth-card-footer'

export function ResetPasswordPage() {
  const { t } = useTranslation()
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')
  const [violations, setViolations] = useState<string[]>([])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setViolations([])

    if (password !== confirmPassword) {
      setError(t('pages.resetPassword.mismatch'))
      return
    }

    if (password.length < 8) {
      setError(t('pages.resetPassword.tooShort'))
      return
    }

    setIsSubmitting(true)

    try {
      const response = await fetch(`${baseURL}/api/v1/identity/users/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
      })

      const data = await response.json()

      if (response.ok) {
        setSuccess(true)
      } else if (data.violations) {
        setViolations(data.violations)
        setError(t('pages.resetPassword.violationsIntro'))
      } else {
        // The API's own error text when it sends one.
        setError(data.error || t('pages.resetPassword.failed'))
      }
    } catch {
      setError(t('pages.resetPassword.offline'))
    } finally {
      setIsSubmitting(false)
    }
  }

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
        <Card className="w-full max-w-md shadow-xl">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-md">
              <AlertCircle className="h-4 w-4 text-red-700 flex-shrink-0" />
              <p className="text-sm text-red-700">
                {t('pages.resetPassword.invalidToken')}
              </p>
            </div>
            <Link to="/login" className="block mt-4">
              <Button variant="ghost" className="w-full">
                <ArrowLeft className="mr-2 h-4 w-4" />
                {t('pages.resetPassword.backToLogin')}
              </Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center shadow-lg">
              <Shield className="h-9 w-9 text-white" />
            </div>
          </div>
          <div>
            <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              OpenIDX
            </CardTitle>
            <CardDescription className="text-base mt-2">
              {t('pages.resetPassword.title')}
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent>
          {success ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-md">
                <CheckCircle className="h-4 w-4 text-green-600 flex-shrink-0" />
                <p className="text-sm text-green-700">
                  {t('pages.resetPassword.success')}
                </p>
              </div>
              <Link to="/login">
                <Button className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700" size="lg">
                  {t('pages.resetPassword.goToLogin')}
                </Button>
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {(error || violations.length > 0) && (
                <div className="p-3 bg-red-50 border border-red-200 rounded-md">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-red-700 flex-shrink-0" />
                    {/* Either one of this page's own messages or the API's. */}
                    <p className="text-sm text-red-700">{error}</p>
                  </div>
                  {violations.length > 0 && (
                    <ul className="mt-2 ml-6 list-disc text-sm text-red-700 space-y-1">
                      {/* Each violation is composed by the password policy. */}
                      {violations.map((v, i) => <li key={i}>{v}</li>)}
                    </ul>
                  )}
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="password">{t('pages.resetPassword.newPassword')}</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder={t('pages.resetPassword.newPasswordPlaceholder')}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={8}
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="confirm-password">
                  {t('pages.resetPassword.confirmPassword')}
                </Label>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder={t('pages.resetPassword.confirmPasswordPlaceholder')}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  minLength={8}
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
                    {t('pages.resetPassword.submitting')}
                  </span>
                ) : (
                  t('pages.resetPassword.submit')
                )}
              </Button>

              <Link to="/login">
                <Button type="button" variant="ghost" className="w-full">
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  {t('pages.resetPassword.backToLogin')}
                </Button>
              </Link>
            </form>
          )}
        </CardContent>

        <AuthCardFooter />
      </Card>

      <div className="absolute bottom-4 text-center w-full">
        <PoweredBy />
      </div>
    </div>
  )
}
