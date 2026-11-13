import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import { Input } from '../components/ui/input'
import { MyPrivilegedAccessSection } from '../components/my-privileged-access-section'
import { PAM_GUIDE_URL } from '../lib/pam-clarity'

/** MyPrivilegedPage: the full-page view of the caller's privileged access. */
export function MyPrivilegedPage() {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t('nav.items.myPrivileged')}</h1>
        <p className="text-muted-foreground">
          {t('pamClarity.page.subtitle')}{' '}
          <a href={PAM_GUIDE_URL} target="_blank" rel="noreferrer" className="text-primary hover:underline">
            {t('pamClarity.howItWorks')}
          </a>
        </p>
      </div>
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          className="pl-10"
          aria-label={t('pamClarity.page.search')}
          placeholder={t('pamClarity.page.search')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <MyPrivilegedAccessSection search={search} showEmpty />
    </div>
  )
}

export default MyPrivilegedPage
