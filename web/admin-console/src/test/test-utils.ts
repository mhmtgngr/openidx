import { vi } from 'vitest'

// Mock the stores - use the @/ path alias to match component imports
vi.mock('@/lib/store', () => ({
  useAppStore: vi.fn(),
  useAuthStore: vi.fn(),
}))

// Export helper functions for tests - import the mocked modules
import { useAppStore, useAuthStore } from '@/lib/store'

// Type the mocked stores properly - cast through unknown to bypass strict typing
type MockedFunction = ReturnType<typeof vi.fn>

export function mockUseAppStore(returnValue: any) {
  (useAppStore as unknown as MockedFunction).mockReturnValue(returnValue)
}

export function mockUseAuthStore(returnValue: any) {
  (useAuthStore as unknown as MockedFunction).mockReturnValue(returnValue)
}

export function getMockedStores() {
  return {
    useAppStore: useAppStore as unknown as MockedFunction,
    useAuthStore: useAuthStore as unknown as MockedFunction,
  }
}
