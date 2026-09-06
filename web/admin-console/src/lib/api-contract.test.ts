import { describe, it, expect } from 'vitest'

// Guards the frontend↔backend API contract.
//
// admin-api registers its routes under `/api/v1/*` and nothing under
// `/api/v1/admin/*` (internal/admin/service.go registers into a `/api/v1`
// group). Both routers in front of it forward the path VERBATIM, with no
// rewrite: APISIX's catch-all rule sends `/api/*` to admin-api unchanged
// (deployments/apisix-edge/seed-edge-routes.sh, `openidx-api-admin`), and
// gateway-service proxies `/api/v1/admin/*path` straight through
// (cmd/gateway-service/main.go, internal/gateway/routes/admin.go — one
// `router.Any("/*path", proxyRequest(proxy))`, no path surgery).
//
// So the prefix does EXIST on the gateway — it just dead-ends: measured against
// a running stack, `/api/v1/social-providers` answers 200 and
// `/api/v1/admin/social-providers` answers 404, through the gateway and
// directly. That distinction matters, because the earlier version of this
// comment claimed no such prefix was registered anywhere; a reader who greps,
// finds `router.Group("/api/v1/admin")`, and concludes the test is stale would
// delete the one thing standing between the console and a batch of 404s. A
// batch of pages had already drifted this way once; the e2e suite hid it by
// mocking those URLs.
//
// This test fails if that prefix reappears. If you're adding an admin-api call,
// use `/api/v1/<resource>` (e.g. `/api/v1/social-providers`), not
// `/api/v1/admin/<resource>`.
//
// Response SHAPES are a different failure (200 with the wrong keys) and are
// gated by tools/contractcheck against the running stack in the CI smoke job.
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
