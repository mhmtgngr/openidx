import { useAppStore, useOrgStore } from '@/lib/store'
import { useAuth } from '@/lib/auth'
import { api } from '@/lib/api'
import { Menu, Bell, Search, Building2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useQuery, useQueryClient } from '@tanstack/react-query'

interface Organization {
  id: string
  name: string
  slug: string
}

// SELF is the sentinel for "act as my own token org" (no X-Org-Slug override).
// Radix Select forbids an empty-string item value, so we map this to null.
const SELF = '__self__'

// TenantSelector lets a platform admin (super_admin) switch the org the console
// acts as. The selected slug is stored (and attached as X-Org-Slug by the api
// interceptor); switching invalidates cached queries so data refetches under
// the new org. It is only mounted for platform admins (see Header), so its
// react-query hooks never run for regular admins.
function TenantSelector() {
  const { selectedOrgSlug, setOrg } = useOrgStore()
  const queryClient = useQueryClient()

  const { data } = useQuery({
    queryKey: ['organizations', 'selector'],
    queryFn: () => api.get<{ organizations: Organization[]; total: number }>('/api/v1/organizations'),
  })

  const orgs = data?.organizations ?? []

  return (
    <div className="flex items-center gap-2">
      <Building2 className="h-4 w-4 text-muted-foreground" />
      <Select
        value={selectedOrgSlug ?? SELF}
        onValueChange={(v) => {
          setOrg(v === SELF ? null : v)
          // Re-fetch everything under the newly selected tenant scope.
          queryClient.invalidateQueries()
        }}
      >
        <SelectTrigger className="h-9 w-48" aria-label="Select organization">
          <SelectValue placeholder="Your organization" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={SELF}>Your organization</SelectItem>
          {orgs.map((o) => (
            <SelectItem key={o.id} value={o.slug}>
              {o.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  )
}

export function Header() {
  const { toggleSidebar } = useAppStore()
  const { hasRole } = useAuth()
  const isPlatformAdmin = hasRole('super_admin')

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b bg-background px-4 lg:px-6">
      <Button
        variant="ghost"
        size="icon"
        onClick={toggleSidebar}
        className="lg:hidden"
      >
        <Menu className="h-5 w-5" />
      </Button>

      <div className="flex-1">
        <form className="relative max-w-md">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search..."
            className="w-full bg-background pl-8 md:w-64 lg:w-80"
          />
        </form>
      </div>

      {isPlatformAdmin && <TenantSelector />}

      <Button variant="ghost" size="icon" className="relative">
        <Bell className="h-5 w-5" />
        <span className="absolute right-1 top-1 flex h-2 w-2 rounded-full bg-destructive" />
      </Button>
    </header>
  )
}
