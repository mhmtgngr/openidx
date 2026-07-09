import { create } from 'zustand'
import type { ViewMode } from '@/config/navigation'

const VIEW_MODE_KEY = 'nav_view_mode'
const COLLAPSED_KEY = 'nav_collapsed_domains'

function loadCollapsed(): string[] {
  try {
    const raw = localStorage.getItem(COLLAPSED_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed.filter((v) => typeof v === 'string') : []
  } catch {
    return []
  }
}

function loadViewMode(): ViewMode {
  const stored = localStorage.getItem(VIEW_MODE_KEY)
  return stored === 'management' || stored === 'reporting' ? stored : 'admin'
}

interface AppState {
  theme: 'light' | 'dark' | 'system'
  setTheme: (theme: 'light' | 'dark' | 'system') => void
  sidebarOpen: boolean
  setSidebarOpen: (open: boolean) => void
  toggleSidebar: () => void
  /** Console lens: full admin, management (operator) or reporting (auditor). */
  viewMode: ViewMode
  setViewMode: (mode: ViewMode) => void
  /** Sidebar domain groups the user collapsed. Domains default to expanded. */
  collapsedDomains: string[]
  toggleDomain: (domain: string) => void
}

export const useAppStore = create<AppState>((set) => ({
  theme: (localStorage.getItem('theme') as 'light' | 'dark' | 'system') || 'system',
  setTheme: (theme) => {
    localStorage.setItem('theme', theme)
    set({ theme })
  },
  sidebarOpen: true,
  setSidebarOpen: (open) => set({ sidebarOpen: open }),
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  viewMode: loadViewMode(),
  setViewMode: (mode) => {
    localStorage.setItem(VIEW_MODE_KEY, mode)
    set({ viewMode: mode })
  },
  collapsedDomains: loadCollapsed(),
  toggleDomain: (domain) =>
    set((state) => {
      const collapsed = state.collapsedDomains.includes(domain)
        ? state.collapsedDomains.filter((d) => d !== domain)
        : [...state.collapsedDomains, domain]
      localStorage.setItem(COLLAPSED_KEY, JSON.stringify(collapsed))
      return { collapsedDomains: collapsed }
    }),
}))

interface AuthUser {
  id: string
  email: string
  name: string
  role: string
}

interface AuthState {
  user: AuthUser | null
  setUser: (user: AuthUser | null) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  setUser: (user) => set({ user }),
  logout: () => {
    localStorage.removeItem('token')
    localStorage.removeItem('refresh_token')
    localStorage.removeItem('selected_org_slug')
    set({ user: null })
  },
}))

// Multi-tenancy: the org the console is acting as. Regular admins are fixed to
// their own token org; platform admins (super_admin) can switch via the header
// selector. The selected slug is persisted so the axios request interceptor
// (lib/api.ts) can attach it as X-Org-Slug without importing the store.
const ORG_SLUG_KEY = 'selected_org_slug'

interface OrgState {
  selectedOrgSlug: string | null
  setOrg: (slug: string | null) => void
}

export const useOrgStore = create<OrgState>((set) => ({
  selectedOrgSlug: localStorage.getItem(ORG_SLUG_KEY),
  setOrg: (slug) => {
    if (slug) {
      localStorage.setItem(ORG_SLUG_KEY, slug)
    } else {
      localStorage.removeItem(ORG_SLUG_KEY)
    }
    set({ selectedOrgSlug: slug })
  },
}))
