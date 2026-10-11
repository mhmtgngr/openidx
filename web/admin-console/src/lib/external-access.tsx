import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Input } from '../components/ui/input'
import { api } from './api'

// What the external-users page and the vendor engagements share: the vendor
// organization's API view, the vendor list query, the sponsor picker and the
// error text a refused change shows.

export interface VendorOrg {
  id: string
  name: string
  status: string
  contact_name: string
  contact_email: string
  contract_start?: string | null
  contract_end?: string | null
  allowed_email_domains: string[] | null
  default_expiry_days: number
  default_sponsor_user_id: string
  notes: string
  closed_at?: string
  external_users?: Record<string, number>
  // On a closed list, the vendor's users ask for and launch only the targets
  // opened to it (invariant I11 of the third-party access framework).
  closed_list?: boolean
  // I13: the vendor's users reach, launch and ask for a target only inside a
  // running engagement that covers it.
  require_engagement?: boolean
}

export type ApiError = { response?: { data?: { error?: string } }; message?: string }
export const apiErrorText = (err: unknown, fallback: string) =>
  (err as ApiError)?.response?.data?.error || fallback

// ---- Sponsor picker ----

interface Candidate { id: string; label: string }

// An enabled internal user of the organization: the only kind the identity
// service accepts as a sponsor (externalid.CheckSponsor). The filter here is a
// convenience; the route refuses anyone else.
function toCandidate(u: Record<string, unknown>): Candidate | null {
  const userType = String(u.userType ?? u.user_type ?? 'internal')
  const enabled = Boolean(u.enabled ?? u.active ?? false)
  if (userType === 'external' || userType === 'service' || !enabled) return null
  const name = (u.name ?? {}) as Record<string, unknown>
  const emails = (u.emails ?? []) as Array<{ value?: string }>
  const username = String(u.userName ?? u.username ?? '')
  const full = [name.givenName, name.familyName].filter(Boolean).join(' ')
  const email = String(emails[0]?.value ?? u.email ?? '')
  return { id: String(u.id ?? ''), label: `${full || username}${email ? ` <${email}>` : ''}` }
}

export function SponsorPicker({ id, value, onChange, optional }: {
  id: string
  value: string
  onChange: (v: string) => void
  optional?: boolean
}) {
  const { t } = useTranslation()
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  useEffect(() => {
    const h = setTimeout(() => setDebounced(search.trim()), 250)
    return () => clearTimeout(h)
  }, [search])
  const { data: candidates = [] } = useQuery({
    queryKey: ['sponsor-candidates', debounced],
    queryFn: async () => {
      const params = new URLSearchParams({ offset: '0', limit: '50' })
      if (debounced) params.set('search', debounced)
      const res = await api.getWithHeaders<Record<string, unknown>[]>(`/api/v1/identity/users?${params.toString()}`)
      return (res.data || []).map(toCandidate).filter((c): c is Candidate => c !== null)
    },
  })
  return (
    <div className="space-y-2">
      <Input
        aria-label={t('pages.externalUsers.sponsor.search')}
        placeholder={t('pages.externalUsers.sponsor.search')}
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      <select
        id={id}
        aria-labelledby={`${id}-label`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
      >
        <option value="">{optional ? t('pages.externalUsers.sponsor.default') : t('pages.externalUsers.sponsor.choose')}</option>
        {value && !candidates.some((c) => c.id === value) && (
          <option value={value}>{t('pages.externalUsers.sponsor.current')}</option>
        )}
        {candidates.map((c) => <option key={c.id} value={c.id}>{c.label}</option>)}
      </select>
    </div>
  )
}

export function useVendors() {
  return useQuery({
    queryKey: ['vendor-orgs'],
    queryFn: async () => (await api.get<{ vendor_organizations: VendorOrg[] }>('/api/v1/identity/vendor-orgs')).vendor_organizations ?? [],
  })
}


// ---- The caller's own vendor (vendor portal) ----

export interface MyVendorEngagement {
  id: string
  title: string
  purpose: string
  ticket_ref: string
  sponsor_name: string
  starts_at: string
  ends_at: string
  state: 'running' | 'scheduled'
  targets: Array<{ target_type: 'application' | 'pam_entry' | 'device'; target_id: string; name: string }>
}

export interface MyVendor {
  external: boolean
  vendor?: { id: string; name: string; require_engagement: boolean; closed_list: boolean }
  account_status?: string
  account_expires_at?: string | null
  sponsor?: { name: string; email: string }
  engagements?: MyVendorEngagement[]
}

// useVendorSelf reads GET /api/v1/access/my/vendor: whether the caller is an
// external (vendor) user, and if so their vendor, sponsor and engagements.
// The token does not carry the user type, so this is how the console knows.
// Staff never are external (an external user holds only the user role), so
// callers pass enabled=false for them and nothing is fetched.
export function useVendorSelf(enabled: boolean) {
  return useQuery({
    queryKey: ['my-vendor'],
    enabled,
    staleTime: 60_000,
    queryFn: async () => (await api.get<MyVendor>('/api/v1/access/my/vendor')) ?? { external: false },
  })
}
