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
    set({ user: null })
  },
}))
