import { describe, it, expect } from 'vitest'

// Guards the frontend↔backend API contract.
//
// The admin-api service registers every route directly under `/api/v1/*`
// (verified against its live gin router and api/openapi/admin-api.yaml) — there
// is NO `/api/v1/admin/*` prefix, and neither APISIX nor the gateway rewrites
// one in. A batch of pages had drifted to calling `/api/v1/admin/...`, which
// 404s in every deployment; the e2e suite hid it by mocking those URLs.
//
// This test fails if that prefix reappears. If you're adding an admin-api call,
// use `/api/v1/<resource>` (e.g. `/api/v1/social-providers`), not
// `/api/v1/admin/<resource>`.
const sources = import.meta.glob('/src/**/*.{ts,tsx}', {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>

describe('frontend API contract', () => {
  it('never calls the non-existent /api/v1/admin/ prefix', () => {
    const offenders: string[] = []
    for (const [path, content] of Object.entries(sources)) {
      if (path.endsWith('api-contract.test.ts')) continue
      const lines = content.split('\n')
      lines.forEach((line, i) => {
        if (line.includes('/api/v1/admin/')) {
          offenders.push(`${path}:${i + 1}`)
        }
      })
    }
    expect(offenders, `Use /api/v1/<resource>, not /api/v1/admin/<resource>:\n${offenders.join('\n')}`).toEqual([])
  })
})
