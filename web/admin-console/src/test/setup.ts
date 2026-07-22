import '@testing-library/jest-dom'
import { vi, afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// Cleanup after each test
afterEach(() => {
  cleanup()
})

// Mock IntersectionObserver
class MockIntersectionObserver {
  observe = vi.fn()
  disconnect = vi.fn()
  unobserve = vi.fn()
}

Object.defineProperty(window, 'IntersectionObserver', {
  writable: true,
  value: MockIntersectionObserver,
})

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock ResizeObserver
class MockResizeObserver {
  observe = vi.fn()
  disconnect = vi.fn()
  unobserve = vi.fn()
}

Object.defineProperty(window, 'ResizeObserver', {
  writable: true,
  value: MockResizeObserver,
})

// Mock scrollTo
window.scrollTo = vi.fn() as unknown as typeof window.scrollTo

// Mock crypto.getRandomValues for PKCE
Object.defineProperty(window, 'crypto', {
  value: {
    getRandomValues: (arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) {
        arr[i] = Math.floor(Math.random() * 256)
      }
      return arr
    },
    subtle: {
      digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    },
  },
})

// Mock hasPointerCapture for Radix UI components (jsdom lacks pointer-capture APIs)
if (!HTMLElement.prototype.hasPointerCapture) {
  HTMLElement.prototype.hasPointerCapture = vi.fn(() => false)
}
if (!HTMLElement.prototype.setPointerCapture) {
  HTMLElement.prototype.setPointerCapture = vi.fn()
}
if (!HTMLElement.prototype.releasePointerCapture) {
  HTMLElement.prototype.releasePointerCapture = vi.fn()
}

// Mock getAnimations for Radix UI (jsdom lacks the Web Animations API)
if (!Element.prototype.getAnimations) {
  Element.prototype.getAnimations = vi.fn(() => [])
}

// Mock scrollIntoView for Radix UI Select. jsdom (unlike happy-dom) does not
// implement Element.prototype.scrollIntoView, and @radix-ui/react-select calls
// it when the listbox mounts, which otherwise throws an unhandled rejection
// ("candidate?.scrollIntoView is not a function") and fails Select-based tests.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = vi.fn()
}

// Mock pointer events for Radix UI
if (!window.PointerEvent) {
  ;(window as any).PointerEvent = class PointerEvent extends MouseEvent {
    constructor(
      type: string,
      init: MouseEventInit & { pointerId?: number; pointerType?: string }
    ) {
      super(type, init)
    }
  } as any
}

