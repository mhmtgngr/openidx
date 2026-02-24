import { vi } from 'vitest'

// Mock the stores - use the @/ path alias to match component imports
vi.mock('@/lib/store', () => ({
  useAppStore: vi.fn(() => ({
    sidebarOpen: true,
    toggleSidebar: vi.fn(),
  })),
  useAuthStore: vi.fn(() => ({
    user: { name: 'Test User', email: 'test@example.com', role: 'Admin' },
    logout: vi.fn(),
  })),
}))

// Export helper functions for tests
export function mockUseAppStore(returnValue: any) {
  const { useAppStore } = vi.mocked('@/lib/store')
  useAppStore.mockReturnValue(returnValue)
}

export function mockUseAuthStore(returnValue: any) {
  const { useAuthStore } = vi.mocked('@/lib/store')
  useAuthStore.mockReturnValue(returnValue)
}

export function getMockedStores() {
  const { useAppStore, useAuthStore } = vi.mocked('@/lib/store')
  return { useAppStore, useAuthStore }
}
