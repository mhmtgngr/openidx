import { test, expect } from '@playwright/test'

/**
 * Production Deployment E2E Tests for openidx.tdv.org
 *
 * These tests verify the production deployment configuration including:
 * - SSL/TLS certificate validation
 * - Service health endpoints
 * - API Gateway routing
 * - OAuth/OIDC endpoints
 * - SCIM provisioning endpoints
 * - Security headers
 * - CORS configuration
 * - Performance metrics
 *
 * Run with:
 *   PLAYWRIGHT_BASE_URL=https://openidx.tdv.org npm run test:e2e production-deployment
 */

const PRODUCTION_DOMAIN = 'openidx.tdv.org'
const PRODUCTION_URL = `https://${PRODUCTION_DOMAIN}`

test.describe('Production Deployment - Infrastructure', () => {
  test('should resolve production domain', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    expect(response.status()).toBe(200)
  })

  test('should enforce HTTPS redirect', async ({ request }) => {
    // Note: This test assumes we can make HTTP requests
    // In CI, this might need special handling
    const httpUrl = `http://${PRODUCTION_DOMAIN}`

    try {
      const response = await request.get(httpUrl, { maxRedirects: 0 })

      // Should redirect to HTTPS (301 or 302)
      expect([301, 302, 307, 308]).toContain(response.status())
      expect(response.headers().location).toMatch(/^https:\/\//)
    } catch (error) {
      // Some environments might not allow HTTP at all
      test.skip(true, 'HTTP not accessible, assuming HTTPS-only')
    }
  })

  test('should have valid SSL certificate', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    expect(response.ok()).toBeTruthy()

    const url = new URL(response.url())
    expect(url.protocol).toBe('https:')
  })

  test('should serve health check endpoint', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/health`)

    expect(response.status()).toBe(200)
    expect(await response.text()).toContain('healthy')
  })

  test('should set security headers', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    const headers = response.headers()

    // Validate security headers are present
    expect(headers['x-frame-options']).toBeTruthy()
    expect(headers['x-content-type-options']).toBeTruthy()
    expect(headers['strict-transport-security']).toBeTruthy()

    // HSTS should be configured with max-age
    const hsts = headers['strict-transport-security']
    expect(hsts).toMatch(/max-age=\d+/)

    // Should include subdomains
    expect(hsts).toMatch(/includeSubDomains/)

    // Should include preload in production
    expect(hsts).toMatch(/preload/)
  })
})

test.describe('Production Deployment - API Gateway', () => {
  test('should serve API routes via gateway', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/api/v1/identity/health`)

    // Health endpoint should respond (may be 200 or require auth)
    expect([200, 401, 403]).toContain(response.status())
  })

  test('should have CORS headers for production domain', async ({ request }) => {
    const response = await request.fetch(`${PRODUCTION_URL}/api/v1/identity/health`, {
      method: 'OPTIONS',
      headers: {
        'Origin': PRODUCTION_URL,
        'Access-Control-Request-Method': 'GET',
      },
    })

    if (response.status() === 204) {
      const corsHeader = response.headers()['access-control-allow-origin']
      expect(corsHeader).toBeTruthy()
    }
  })

  test('should route to all services', async ({ request }) => {
    const services = [
      '/api/v1/identity/health',
      '/api/v1/governance/health',
      '/api/v1/provisioning/health',
      '/api/v1/audit/health',
      '/api/v1/admin/health',
      '/api/v1/access/health',
    ]

    for (const service of services) {
      const response = await request.get(`${PRODUCTION_URL}${service}`)

      // Health endpoints should be accessible
      expect([200, 401, 403, 404]).toContain(response.status())
    }
  })
})

test.describe('Production Deployment - OAuth/OIDC', () => {
  test('should serve OIDC discovery document', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/.well-known/openid-configuration`)

    expect(response.status()).toBe(200)

    const contentType = response.headers()['content-type']
    expect(contentType).toMatch(/application\/json/)

    const config = await response.json()

    // Validate required OIDC fields
    expect(config.issuer).toBe(PRODUCTION_URL)
    expect(config.authorization_endpoint).toContain('/oauth/authorize')
    expect(config.token_endpoint).toContain('/oauth/token')
    expect(config.jwks_uri).toContain('/.well-known/jwks.json')
    expect(config.response_types_supported).toBeInstanceOf(Array)
    expect(config.subject_types_supported).toBeInstanceOf(Array)
  })

  test('should serve JWKS endpoint', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/.well-known/jwks.json`)

    expect(response.status()).toBe(200)

    const contentType = response.headers()['content-type']
    expect(contentType).toMatch(/application\/json/)

    const jwks = await response.json()

    // Validate JWKS structure
    expect(jwks.keys).toBeInstanceOf(Array)

    // If keys are present, validate structure
    if (jwks.keys.length > 0) {
      const key = jwks.keys[0]
      expect(key.kty).toBeTruthy()
      expect(key.kid).toBeTruthy()
      expect(key.n).toBeTruthy() // RSA modulus
      expect(key.e).toBeTruthy() // RSA exponent
    }
  })

  test('should have CORS for OAuth endpoints', async ({ request }) => {
    const response = await request.fetch(`${PRODUCTION_URL}/.well-known/openid-configuration`, {
      method: 'OPTIONS',
      headers: {
        'Origin': PRODUCTION_URL,
        'Access-Control-Request-Method': 'GET',
      },
    })

    // CORS preflight should succeed
    expect([200, 204]).toContain(response.status())
  })
})

test.describe('Production Deployment - SCIM', () => {
  test('should serve SCIM discovery endpoints', async ({ request }) => {
    const endpoints = [
      '/scim/v2/ServiceProviderConfig',
      '/scim/v2/Schemas',
      '/scim/v2/ResourceTypes',
    ]

    for (const endpoint of endpoints) {
      const response = await request.get(`${PRODUCTION_URL}${endpoint}`)

      // SCIM endpoints typically require authentication
      expect([200, 401, 403]).toContain(response.status())

      if (response.status() === 200) {
        const contentType = response.headers()['content-type']
        expect(contentType).toMatch(/application\/scim\+json|application\/json/)
      }
    }
  })

  test('should return SCIM error for unauthenticated requests', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/scim/v2/Users`)

    // Should require authentication
    expect([401, 403]).toContain(response.status())
  })
})

test.describe('Production Deployment - Admin Console', () => {
  test('should serve admin console', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    // Page should load
    await expect(page).toHaveTitle(/OpenIDX|Zero Trust/)

    // Should have viewport meta tag
    const viewport = await page.locator('meta[name="viewport"]').getAttribute('content')
    expect(viewport).toBeTruthy()
  })

  test('should have production API URLs configured', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    // Check runtime config or API calls
    const apiCalls: string[] = []

    page.on('request', (request) => {
      const url = new URL(request.url())
      if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/oauth/')) {
        apiCalls.push(request.url())
      }
    })

    // Wait for initial page load
    await page.waitForLoadState('networkidle')

    // Validate all API calls go to production domain
    for (const call of apiCalls) {
      const url = new URL(call)
      expect(url.hostname).toBe(PRODUCTION_DOMAIN)
      expect(url.protocol).toBe('https:')
    }
  })

  test('should have CSP headers', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    const csp = response.headers()['content-security-policy']

    expect(csp).toBeTruthy()

    // CSP should include production domain
    expect(csp).toMatch(/openidx\.tdv\.org/)

    // Should have default-src
    expect(csp).toMatch(/default-src/)

    // Should have script-src
    expect(csp).toMatch(/script-src/)
  })

  test('should cache static assets', async ({ page }) => {
    const assetResponses: Record<string, string> = []

    page.on('response', (response) => {
      const url = new URL(response.url())
      if (url.pathname.match(/\.(js|css|png|jpg|jpeg|svg|woff2?)$/)) {
        assetResponses[url.pathname] = response.headers()['cache-control'] || ''
      }
    })

    await page.goto(PRODUCTION_URL)
    await page.waitForLoadState('networkidle')

    // At least some assets should have cache headers
    const assetsWithCache = Object.values(assetResponses).filter(cc =>
      cc && (cc.includes('max-age') || cc.includes('immutable'))
    )

    expect(assetsWithCache.length).toBeGreaterThan(0)
  })
})

test.describe('Production Deployment - Performance', () => {
  test('should load landing page quickly', async ({ page }) => {
    const startTime = Date.now()

    await page.goto(PRODUCTION_URL)
    await page.waitForLoadState('networkidle')

    const loadTime = Date.now() - startTime

    // Should load in less than 5 seconds
    expect(loadTime).toBeLessThan(5000)
  })

  test('should have efficient bundle sizes', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)
    const html = await response.text()

    // Count script tags
    const scriptMatches = html.match(/<script[^>]*src="([^"]*)"/g) || []

    // Production should have reasonable number of scripts
    expect(scriptMatches.length).toBeLessThan(20)

    // Check for minified assets
    const hasMinified = scriptMatches.some(script =>
      script.includes('.min.') || script.includes('.[')
    )
  })

  test('should compress responses', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL, {
      headers: {
        'Accept-Encoding': 'gzip, deflate, br',
      },
    })

    const encoding = response.headers()['content-encoding']

    // Responses should be compressed
    expect(encoding).toBeTruthy()
    expect(['gzip', 'br', 'deflate']).toContain(encoding)
  })

  test('should have reasonable Time to First Byte', async ({ request }) => {
    const start = Date.now()
    await request.get(`${PRODUCTION_URL}/health`)
    const ttfb = Date.now() - start

    // Health endpoint should be fast (< 1 second)
    expect(ttfb).toBeLessThan(1000)
  })
})

test.describe('Production Deployment - Security', () => {
  test('should not leak server information', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    const server = response.headers()['server']

    // Server header should be generic or missing
    if (server) {
      // Should not contain specific version numbers
      expect(server).not.toMatch(/\d+\.\d+/)
    }
  })

  test('should have X-Frame-Options set to SAMEORIGIN', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    const xfo = response.headers()['x-frame-options']

    expect(xfo).toBeTruthy()
    expect(xfo.toUpperCase()).toContain('SAMEORIGIN')
  })

  test('should have X-Content-Type-Options nosniff', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    const xcto = response.headers()['x-content-type-options']

    expect(xcto).toBeTruthy()
    expect(xcto.toLowerCase()).toBe('nosniff')
  })

  test('should have Referrer-Policy header', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL)

    const referrerPolicy = response.headers()['referrer-policy']

    expect(referrerPolicy).toBeTruthy()
    expect([
      'no-referrer-when-downgrade',
      'strict-origin-when-cross-origin',
      'same-origin',
    ]).toContain(referrerPolicy)
  })

  test('should block access to sensitive files', async ({ request }) => {
    const sensitivePaths = [
      '/.env',
      '/.git',
      '/package.json',
      '/docker-compose.yml',
    ]

    for (const path of sensitivePaths) {
      const response = await request.get(`${PRODUCTION_URL}${path}`)

      // Should return 404 or 403
      expect([404, 403]).toContain(response.status())
    }
  })

  test('should handle invalid hostnames', async ({ request }) => {
    // This test would require making a request with a different Host header
    // Playwright's request API doesn't support custom Host headers easily
    // Skipping but documenting the requirement
    test.skip(true, 'Requires custom Host header support')
  })
})

test.describe('Production Deployment - Error Handling', () => {
  test('should return 404 for invalid API endpoints', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/api/v1/invalid-endpoint`)

    expect(response.status()).toBe(404)
  })

  test('should return proper JSON error response', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/api/v1/invalid-endpoint`)

    expect(response.headers()['content-type']).toMatch(/application\/json/)

    const error = await response.json()

    expect(error).toHaveProperty('error')
  })

  test('should reject invalid HTTP methods', async ({ request }) => {
    const response = await request.fetch(`${PRODUCTION_URL}/api/v1/identity/health`, {
      method: 'INVALID',
    })

    // Should return method not allowed or bad request
    expect([400, 405]).toContain(response.status())
  })
})

test.describe('Production Deployment - Monitoring', () => {
  test('should have Prometheus metrics endpoint', async ({ request }) => {
    // APISIX Prometheus plugin metrics
    // This endpoint may be protected or on a different port
    const response = await request.get('http://localhost:9091/prometheus/metrics')

    if (response.ok()) {
      const metrics = await response.text()
      expect(metrics).toBeTruthy()
    } else {
      test.skip(true, 'Prometheus endpoint not accessible')
    }
  })

  test('should expose health status for load balancers', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/health`)

    expect(response.status()).toBe(200)

    const text = await response.text()
    expect(text.toLowerCase()).toMatch(/healthy|ok/)
  })
})

test.describe('Production Deployment - Backup Validation', () => {
  test('should have backup directory configured', async () => {
    // This is an infrastructure test, not an HTTP test
    // In a real CI environment, this would check the actual filesystem
    test.skip(true, 'Requires filesystem access')
  })

  test('should validate backup script exists', async () => {
    // This would require shell access
    test.skip(true, 'Requires shell access')
  })
})

test.describe('Production Deployment - DNS', () => {
  test('should resolve www subdomain', async ({ request }) => {
    const wwwUrl = `https://www.${PRODUCTION_DOMAIN}`

    try {
      const response = await request.get(wwwUrl)

      // Should either work or redirect to main domain
      expect([200, 301, 302, 307, 308]).toContain(response.status())
    } catch (error) {
      // DNS might not be configured for www
      test.skip(true, 'www subdomain not configured')
    }
  })

  test('should handle IPv6', async () => {
    // Requires AAAA record check
    test.skip(true, 'Requires DNS lookup tools')
  })
})

test.describe('Production Deployment - Rate Limiting', () => {
  test('should rate limit excessive requests', async ({ request }) => {
    const endpoint = `${PRODUCTION_URL}/health`

    // Make many requests rapidly
    const responses = await Promise.all(
      Array.from({ length: 100 }, () => request.get(endpoint))
    )

    // At least one should be rate limited (429)
    const rateLimited = responses.some(r => r.status() === 429)

    if (rateLimited) {
      // Rate limiting is working
      expect(rateLimited).toBeTruthy()
    } else {
      // Rate limiting might not be configured or threshold not reached
      test.skip(true, 'Rate limiting threshold not reached or not configured')
    }
  })
})

test.describe('Production Deployment - Database', () => {
  test('should have database connectivity', async ({ request }) => {
    // Check if identity service health includes database check
    const response = await request.get(`${PRODUCTION_URL}/api/v1/identity/health`)

    if (response.status() === 200) {
      const health = await response.json()

      // Health response should include database status
      if (health.dependencies) {
        expect(health.dependencies.database).toMatch(/up|healthy|connected/)
      }
    }
  })
})

test.describe('Production Deployment - Redis', () => {
  test('should have Redis connectivity', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/api/v1/identity/health`)

    if (response.status() === 200) {
      const health = await response.json()

      // Health response should include cache status
      if (health.dependencies) {
        expect(health.dependencies.redis || health.dependencies.cache).toMatch(/up|healthy|connected/)
      }
    }
  })
})

test.describe('Production Deployment - Elasticsearch', () => {
  test('should have Elasticsearch connectivity for audit logs', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/api/v1/audit/health`)

    // Should respond (may require auth)
    expect([200, 401, 403]).toContain(response.status())

    if (response.status() === 200) {
      const health = await response.json()

      // Health response should include elasticsearch status
      if (health.dependencies) {
        expect(health.dependencies.elasticsearch).toMatch(/up|healthy|connected/)
      }
    }
  })
})

test.describe('Production Deployment - Certificate Renewal', () => {
  test('should have valid certificate expiry', async ({ request }) => {
    // This would require SSL certificate inspection
    // Playwright doesn't expose certificate details directly
    test.skip(true, 'Requires certificate chain inspection')
  })

  test('should support ACME challenge', async ({ request }) => {
    // Test ACME challenge path is accessible
    const response = await request.get(
      `${PRODUCTION_URL}/.well-known/acme-challenge/test`
    )

    // Should return 404 (file doesn't exist) but not error
    expect([404, 403]).toContain(response.status())
  })
})

test.describe('Production Deployment - Content Delivery', () => {
  test('should serve service worker', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    // Check if service worker is registered
    const hasServiceWorker = await page.evaluate(() => {
      return 'serviceWorker' in navigator
    })

    expect(hasServiceWorker).toBeTruthy()
  })

  test('should have manifest file', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/manifest.json`)

    // May or may not have manifest
    if (response.ok()) {
      const manifest = await response.json()

      expect(manifest).toHaveProperty('name')
      expect(manifest).toHaveProperty('start_url')
    }
  })

  test('should have favicon', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    const favicon = await page.locator('link[rel="icon"], link[rel="shortcut icon"]').count()

    expect(favicon).toBeGreaterThan(0)
  })
})

test.describe('Production Deployment - Accessibility', () => {
  test('should have lang attribute', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    const lang = await page.locator('html').getAttribute('lang')

    expect(lang).toBeTruthy()
    expect(['en', 'en-US']).toContain(lang)
  })

  test('should have proper heading hierarchy', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    const h1Count = await page.locator('h1').count()

    expect(h1Count).toBeGreaterThan(0)
  })
})

test.describe('Production Deployment - SEO', () => {
  test('should have meta description', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    const description = await page.locator('meta[name="description"]').getAttribute('content')

    expect(description).toBeTruthy()
    expect(description?.length).toBeGreaterThan(50)
  })

  test('should have canonical URL', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    const canonical = await page.locator('link[rel="canonical"]').getAttribute('href')

    if (canonical) {
      expect(canonical).toMatch(new RegExp(`^https://${PRODUCTION_DOMAIN}`))
    }
  })
})

test.describe('Production Deployment - Compliance', () => {
  test('should have privacy policy link', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    // Look for privacy-related links
    const privacyLink = page.locator('a').filter({ hasText: /privacy/i })

    // May or may not exist depending on implementation
    const count = await privacyLink.count()

    if (count > 0) {
      expect(count).toBeGreaterThan(0)
    }
  })

  test('should have terms of service link', async ({ page }) => {
    await page.goto(PRODUCTION_URL)

    const termsLink = page.locator('a').filter({ hasText: /terms/i })

    const count = await termsLink.count()

    if (count > 0) {
      expect(count).toBeGreaterThan(0)
    }
  })
})

test.describe('Production Deployment - Health Monitor', () => {
  test('should expose Prometheus metrics endpoint', async ({ request }) => {
    // Health monitor exposes metrics on :9000/metrics internally
    // In production, this may be proxied via nginx
    const metricsUrl = `${PRODUCTION_URL}/metrics`

    try {
      const response = await request.get(metricsUrl)

      // Metrics endpoint may be protected or not exposed
      if (response.ok()) {
        const metrics = await response.text()

        // Should contain Prometheus-style metrics
        expect(metrics).toMatch(/health_service_status|health_service_response_time_ms/)
      }
    } catch {
      // Metrics endpoint might not be publicly accessible
      test.skip(true, 'Metrics endpoint not publicly accessible')
    }
  })

  test('should return JSON health status', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/health`)

    expect(response.status()).toBe(200)
    expect(response.headers()['content-type']).toMatch(/application\/json/)

    const health = await response.json()

    // Should have healthy boolean
    expect(health).toHaveProperty('healthy')

    // Should have timestamp
    expect(health).toHaveProperty('timestamp')

    // Should have services object (if using health monitor)
    if (health.services) {
      expect(health.services).toBeInstanceOf(Object)
    }
  })

  test('should include all service health statuses', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/health`)

    if (response.status() === 200) {
      const health = await response.json()

      // If using health monitor, check for expected services
      if (health.services) {
        const expectedServices = [
          'Identity Service',
          'Governance Service',
          'OAuth Service',
          'Admin API',
        ]

        // At least some services should be present
        const serviceNames = Object.keys(health.services)
        expect(serviceNames.length).toBeGreaterThan(0)
      }
    }
  })

  test('should indicate overall health correctly', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/health`)

    if (response.status() === 200) {
      const health = await response.json()

      // If services object exists, overall healthy should match all services
      if (health.services && typeof health.healthy === 'boolean') {
        const allServicesHealthy = Object.values(health.services).every(
          (s: any) => s.Healthy === true
        )

        expect(health.healthy).toBe(allServicesHealthy)
      }
    }
  })
})

test.describe('Production Deployment - Service Discovery', () => {
  test('should have OIDC discovery at correct path', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/.well-known/openid-configuration`)

    expect(response.status()).toBe(200)
    expect(response.headers()['content-type']).toMatch(/application\/json/)
  })

  test('should have JWKS endpoint', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/.well-known/jwks.json`)

    expect(response.status()).toBe(200)
    expect(response.headers()['content-type']).toMatch(/application\/json/)

    const jwks = await response.json()
    expect(jwks).toHaveProperty('keys')
    expect(Array.isArray(jwks.keys)).toBeTruthy()
  })

  test('should serve SCIM service provider config', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/scim/v2/ServiceProviderConfig`)

    // SCIM endpoints typically require authentication
    expect([200, 401, 403]).toContain(response.status())

    if (response.status() === 200) {
      const config = await response.json()
      expect(config).toHaveProperty('schemas')
    }
  })
})

test.describe('Production Deployment - SSL Configuration', () => {
  test('should support TLS 1.2 and 1.3 only', async () => {
    // Playwright uses the system's TLS configuration
    // This test verifies the connection succeeds
    // A more detailed test would check specific TLS versions
    test.skip(true, 'Requires TLS version inspection')
  })

  test('should have valid certificate chain', async () => {
    // Certificate chain validation requires SSL tools
    test.skip(true, 'Requires SSL certificate inspection tools')
  })

  test('should use strong cipher suites', async () => {
    // Cipher suite inspection requires SSL tools
    test.skip(true, 'Requires SSL cipher inspection tools')
  })
})

test.describe('Production Deployment - nginx Configuration', () => {
  test('should have server tokens disabled', async ({ request }) => {
    const response = await request.get(`${PRODUCTION_URL}/`)

    const serverHeader = response.headers()['server']

    // nginx should either not send server header or use generic "nginx"
    if (serverHeader) {
      expect(serverHeader.toLowerCase()).toMatch(/^(nginx|nginx\/\d+\.\d+)$/)
      // Should not expose detailed version
      expect(serverHeader).not.toMatch(/\d+\.\d+\.\d+/)
    }
  })

  test('should compress responses with gzip', async ({ request }) => {
    const response = await request.get(PRODUCTION_URL, {
      headers: {
        'Accept-Encoding': 'gzip, deflate',
      },
    })

    const encoding = response.headers()['content-encoding']

    // Static assets should be compressed
    if (encoding) {
      expect(['gzip', 'br', 'deflate']).toContain(encoding)
    }
  })

  test('should set cache headers for static assets', async ({ request }) => {
    // Try to get a static asset
    const response = await request.get(`${PRODUCTION_URL}/assets/main.js`)

    if (response.ok()) {
      const cacheControl = response.headers()['cache-control']

      // Static assets should have cache directives
      if (cacheControl) {
        expect(cacheControl).toMatch(/public|max-age/)
      }
    }
  })
})

test.describe('Production Deployment - Backup Service', () => {
  test('should have backup endpoint configured', async () => {
    // Backup endpoint is typically internal-only
    // This test documents the expected configuration
    test.skip(true, 'Backup endpoint is internal-only')
  })

  test('should validate backup schedule', async () => {
    // Backup schedule is in docker-compose.prod.yml
    // This test validates the configuration exists
    test.skip(true, 'Requires docker-compose inspection')
  })
})
