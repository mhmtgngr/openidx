import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import type { AxiosAdapter } from 'axios'
import { api } from './api'

// The request interceptor sends the organization the selector chose as
// X-Org-Slug. The selector used to show for any super_admin, so a selection
// can be left in storage for a token the API refuses in another organization.
// Only a platform admin's requests may carry it; anyone else's go to their
// own organization, as their token says.
const DEFAULT_ORG = '00000000-0000-0000-0000-000000000010'
const OTHER_ORG = '11111111-1111-1111-1111-111111111111'

function token(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${b64({ alg: 'RS256', typ: 'at+jwt' })}.${b64(claims)}.sig`
}

// Answers with the headers the request left the interceptor with.
const echo: AxiosAdapter = async (config) => ({
  data: { slug: config.headers['X-Org-Slug'] ?? null, auth: config.headers.Authorization ?? null },
  status: 200,
  statusText: 'OK',
  headers: {},
  config,
})

async function sent() {
  return api.get<{ slug: string | null; auth: string | null }>('/api/v1/users', { adapter: echo })
}

describe('X-Org-Slug', () => {
  beforeEach(() => {
    localStorage.clear()
    localStorage.setItem('selected_org_slug', 'globex')
  })
  afterEach(() => localStorage.clear())

  it("carries a platform admin's selection", async () => {
    localStorage.setItem('token', token({ roles: ['super_admin'], org_id: DEFAULT_ORG }))
    expect((await sent()).slug).toBe('globex')
  })

  it('carries nothing when a platform admin has chosen their own organization', async () => {
    localStorage.setItem('token', token({ roles: ['super_admin'], org_id: DEFAULT_ORG }))
    localStorage.removeItem('selected_org_slug')
    expect((await sent()).slug).toBeNull()
  })

  it.each([
    ['super_admin of another organization', { roles: ['super_admin'], org_id: OTHER_ORG }],
    ['admin of the default organization', { roles: ['admin'], org_id: DEFAULT_ORG }],
    ['super_admin with no organization', { roles: ['super_admin'] }],
  ])('leaves a stored selection off the requests of a %s', async (_who, claims) => {
    const t = token(claims)
    localStorage.setItem('token', t)
    const got = await sent()
    expect(got.slug).toBeNull()
    // The request is still authenticated; only the organization is dropped.
    expect(got.auth).toBe(`Bearer ${t}`)
  })

  it('leaves it off a request with no token', async () => {
    expect((await sent()).slug).toBeNull()
  })
})
