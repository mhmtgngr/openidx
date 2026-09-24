import { afterEach, describe, expect, it, vi } from 'vitest'
import { resolveOAuthURL } from './oauth-url'

describe('resolveOAuthURL', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('uses VITE_OAUTH_URL when the build sets it', () => {
    vi.stubEnv('VITE_OAUTH_URL', 'https://oauth.example.com')
    vi.stubEnv('VITE_API_URL', 'https://api.example.com')
    expect(resolveOAuthURL()).toBe('https://oauth.example.com')
  })

  it('falls back to the API URL when only that is set', () => {
    vi.stubEnv('VITE_OAUTH_URL', '')
    vi.stubEnv('VITE_API_URL', 'https://api.example.com')
    expect(resolveOAuthURL()).toBe('https://api.example.com')
  })

  it('falls back to the page origin, never to a fixed host, when nothing is set', () => {
    vi.stubEnv('VITE_OAUTH_URL', '')
    vi.stubEnv('VITE_API_URL', '')
    vi.stubEnv('VITE_API_BASE_URL', '')
    expect(resolveOAuthURL()).toBe(window.location.origin)
    expect(resolveOAuthURL()).not.toContain(':8006')
  })
})
