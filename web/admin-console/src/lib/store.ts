import { create } from 'zustand'

interface AppState {
  theme: 'light' | 'dark' | 'system'
  setTheme: (theme: 'light' | 'dark' | 'system') => void
  sidebarOpen: boolean
  setSidebarOpen: (open: boolean) => void
  toggleSidebar: () => void
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
