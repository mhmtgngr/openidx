import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../lib/auth'
import {
  Shield,
  Lock,
  Users,
  Globe,
  CheckCircle,
  ArrowRight,
  Zap,
  Eye,
  Network,
  FileCheck,
  Menu,
  X,
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card, CardContent } from '../components/ui/card'
import { LanguageSwitcher } from '../components/language-switcher'

// Every claim on this page must be checkable against the repository: no
// invented SLAs, trials, pricing, adoption numbers, or dead links. Copy
// lives in the i18n catalogs (src/i18n/locales) — this page is the
// reference extraction for the console's i18n convention.

const repoUrl = 'https://github.com/mhmtgngr/openidx'
const docsUrl = 'https://mhmtgngr.github.io/openidx'

const links = {
  repo: repoUrl,
  docs: docsUrl,
  apiReference: `${repoUrl}/tree/main/api/openapi`,
  issues: `${repoUrl}/issues`,
  contributing: `${repoUrl}/blob/main/CONTRIBUTING.md`,
  changelog: `${repoUrl}/blob/main/CHANGELOG.md`,
  license: `${repoUrl}/blob/main/LICENSE`,
  securityPolicy: `${repoUrl}/blob/main/SECURITY.md`,
  threatModel: `${repoUrl}/blob/main/docs/THREAT-MODEL.md`,
  complianceMapping: `${repoUrl}/blob/main/docs/COMPLIANCE-CONTROL-MAPPING.md`,
}

// Feature card copy comes from the catalog; icons stay here.
const featureDefs = [
  { key: 'zeroTrust', icon: <Shield className="h-6 w-6" /> },
  { key: 'iam', icon: <Users className="h-6 w-6" /> },
  { key: 'mfa', icon: <Lock className="h-6 w-6" /> },
  { key: 'sso', icon: <Globe className="h-6 w-6" /> },
  { key: 'monitoring', icon: <Eye className="h-6 w-6" /> },
  { key: 'governance', icon: <FileCheck className="h-6 w-6" /> },
  { key: 'gateway', icon: <Network className="h-6 w-6" /> },
  { key: 'performance', icon: <Zap className="h-6 w-6" /> },
] as const

// Verifiable facts only: a self-hosted OSS project cannot promise an SLA,
// a latency figure, or anyone's cost savings.
const statDefs = [
  { value: '4', key: 'pillars' },
  { value: '8', key: 'services' },
  { value: '100%', key: 'openSource' },
  { value: '0', key: 'darkPorts' },
] as const

// Product names are not translated.
const integrations = [
  'Active Directory',
  'LDAP',
  'Okta',
  'Azure AD',
  'Google Workspace',
  'Salesforce',
  'Slack',
  'Microsoft Teams',
]

export function LandingPage() {
  const { isAuthenticated, login } = useAuth()
  const navigate = useNavigate()
  const { t } = useTranslation()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true })
    }
  }, [isAuthenticated, navigate])

  const handleLogin = () => {
    login()
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-white">
      {/* Navigation */}
      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled ? 'bg-background/95 backdrop-blur-sm shadow-md' : 'bg-transparent'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                OpenIDX
              </span>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-8">
              <a href="#features" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                {t('landing.nav.features')}
              </a>
              <a href="#integration" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                {t('landing.nav.integrations')}
              </a>
              <a
                href={links.docs}
                target="_blank"
                rel="noreferrer"
                className="text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                {t('landing.nav.documentation')}
              </a>
            </div>

            <div className="hidden md:flex items-center gap-4">
              <LanguageSwitcher />
              <Button variant="ghost" size="sm" onClick={() => navigate('/login')}>
                {t('landing.nav.signIn')}
              </Button>
              <Button
                size="sm"
                className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                onClick={handleLogin}
              >
                {t('landing.nav.getStarted')}
              </Button>
            </div>

            {/* Mobile menu button */}
            <button
              className="md:hidden p-2"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-background border-b">
            <div className="px-4 py-4 space-y-3">
              <a href="#features" className="block text-sm text-muted-foreground hover:text-foreground">
                {t('landing.nav.features')}
              </a>
              <a href="#integration" className="block text-sm text-muted-foreground hover:text-foreground">
                {t('landing.nav.integrations')}
              </a>
              <a
                href={links.docs}
                target="_blank"
                rel="noreferrer"
                className="block text-sm text-muted-foreground hover:text-foreground"
              >
                {t('landing.nav.documentation')}
              </a>
              <div className="pt-3 space-y-2">
                <LanguageSwitcher />
                <Button variant="ghost" size="sm" className="w-full" onClick={() => navigate('/login')}>
                  {t('landing.nav.signIn')}
                </Button>
                <Button
                  size="sm"
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600"
                  onClick={handleLogin}
                >
                  {t('landing.nav.getStarted')}
                </Button>
              </div>
            </div>
          </div>
        )}
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-4xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-blue-50 text-blue-700 text-sm font-medium mb-6">
              <Shield className="h-4 w-4" />
              <span>{t('landing.hero.badge')}</span>
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-foreground leading-tight mb-6">
              {t('landing.hero.titleLead')}{' '}
              <span className="bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                {t('landing.hero.titleHighlight')}
              </span>
            </h1>

            <p className="text-lg sm:text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
              {t('landing.hero.subtitle')}
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12">
              <Button
                size="lg"
                className="bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-base px-8"
                onClick={() => navigate('/login')}
              >
                {t('landing.nav.signIn')}
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
              <Button size="lg" variant="outline" className="text-base px-8" asChild>
                <a href={links.docs} target="_blank" rel="noreferrer">
                  {t('landing.hero.viewDocs')}
                </a>
              </Button>
            </div>

            <div className="flex flex-wrap items-center justify-center gap-6 text-sm text-muted-foreground">
              <div className="flex items-center gap-1">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span>{t('landing.hero.point1')}</span>
              </div>
              <div className="flex items-center gap-1">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span>{t('landing.hero.point2')}</span>
              </div>
              <div className="flex items-center gap-1">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span>{t('landing.hero.point3')}</span>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-16">
            {statDefs.map((stat) => (
              <Card key={stat.key} className="text-center">
                <CardContent className="pt-6">
                  <div className="text-2xl sm:text-3xl font-bold text-primary">{stat.value}</div>
                  <div className="text-sm text-muted-foreground mt-1">
                    {t(`landing.stats.${stat.key}`)}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 bg-background">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-foreground mb-4">
              {t('landing.features.title')}
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              {t('landing.features.subtitle')}
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {featureDefs.map((feature) => (
              <Card key={feature.key} className="border-none shadow-sm hover:shadow-md transition-shadow">
                <CardContent className="p-6">
                  <div className="h-12 w-12 rounded-lg bg-blue-100 text-primary flex items-center justify-center mb-4">
                    {feature.icon}
                  </div>
                  <h3 className="font-semibold text-lg mb-2">
                    {t(`landing.features.${feature.key}.title`)}
                  </h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {t(`landing.features.${feature.key}.description`)}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Integration Section */}
      <section id="integration" className="py-20 px-4 sm:px-6 lg:px-8 bg-muted">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold text-foreground mb-4">
              {t('landing.integrations.title')}
            </h2>
            <p className="text-lg text-muted-foreground">
              {t('landing.integrations.subtitle')}
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 max-w-4xl mx-auto">
            {integrations.map((integration, index) => (
              <div
                key={index}
                className="px-6 py-3 bg-background rounded-full shadow-sm text-sm font-medium text-foreground"
              >
                {integration}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          <Card className="bg-gradient-to-r from-blue-600 to-indigo-700 border-0 text-white">
            <CardContent className="p-12 text-center">
              <h2 className="text-3xl font-bold mb-4">{t('landing.cta.title')}</h2>
              <p className="text-blue-100 mb-8 text-lg">
                {t('landing.cta.subtitle')}
              </p>
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
                <Button
                  size="lg"
                  variant="secondary"
                  className="bg-background text-primary hover:bg-muted px-8"
                  onClick={() => navigate('/login')}
                >
                  {t('landing.nav.signIn')}
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
                <Button
                  size="lg"
                  variant="outline"
                  className="border-white text-white hover:bg-background/10 px-8"
                  asChild
                >
                  <a href={links.repo} target="_blank" rel="noreferrer">
                    {t('landing.cta.viewOnGitHub')}
                  </a>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-4 sm:px-6 lg:px-8 bg-gray-900 text-muted-foreground">
        <div className="max-w-7xl mx-auto">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="flex items-center gap-2 mb-4">
                <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-blue-600 to-indigo-700 flex items-center justify-center">
                  <Shield className="h-5 w-5 text-white" />
                </div>
                <span className="text-xl font-bold text-white">OpenIDX</span>
              </div>
              <p className="text-sm">{t('landing.footer.tagline')}</p>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-4">{t('landing.footer.product')}</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#features" className="hover:text-white transition-colors">{t('landing.nav.features')}</a></li>
                <li><a href="#integration" className="hover:text-white transition-colors">{t('landing.nav.integrations')}</a></li>
                <li><a href={links.docs} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.nav.documentation')}</a></li>
                <li><a href={links.apiReference} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.apiReference')}</a></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-4">{t('landing.footer.project')}</h4>
              <ul className="space-y-2 text-sm">
                <li><a href={links.repo} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">GitHub</a></li>
                <li><a href={links.issues} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.issues')}</a></li>
                <li><a href={links.contributing} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.contributing')}</a></li>
                <li><a href={links.changelog} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.changelog')}</a></li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold text-white mb-4">{t('landing.footer.securityLegal')}</h4>
              <ul className="space-y-2 text-sm">
                <li><a href={links.license} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.license')}</a></li>
                <li><a href={links.securityPolicy} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.securityPolicy')}</a></li>
                <li><a href={links.threatModel} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.threatModel')}</a></li>
                <li><a href={links.complianceMapping} target="_blank" rel="noreferrer" className="hover:text-white transition-colors">{t('landing.footer.complianceMapping')}</a></li>
              </ul>
            </div>
          </div>

          <div className="border-t border-gray-800 pt-8 flex flex-col sm:flex-row items-center justify-between gap-4">
            <p className="text-sm">
              {t('landing.footer.copyright', { year: new Date().getFullYear() })}
            </p>
            <div className="flex items-center gap-4 text-sm">
              <a href={links.repo} target="_blank" rel="noreferrer" className="text-blue-400 hover:text-blue-300">
                {t('landing.footer.sourceOnGitHub')}
              </a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default LandingPage
