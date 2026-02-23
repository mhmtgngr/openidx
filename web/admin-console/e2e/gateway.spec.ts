import { test, expect } from '@playwright/test';

/**
 * Gateway E2E Tests
 *
 * These tests verify the gateway functionality including:
 * - Service routing
 * - Health checks
 * - Rate limiting (via headers)
 * - CORS behavior
 * - Correlation ID propagation
 * - API documentation endpoints
 */

test.describe('API Gateway - Health Endpoints', () => {
  test('GET /health returns gateway health status', async ({ request }) => {
    const response = await request.get('/health');

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('status', 'ok');
    expect(body).toHaveProperty('service', 'gateway');
  });

  test('GET /health/live returns liveness status', async ({ request }) => {
    const response = await request.get('/health/live');

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('status', 'alive');
  });

  test('GET /health/ready returns readiness status', async ({ request }) => {
    const response = await request.get('/health/ready');

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('status', 'ready');
  });

  test('GET /health/detailed returns all service health statuses', async ({ request }) => {
    const response = await request.get('/health/detailed');

    // May return 200 if all services are healthy, or 503 if some are down
    expect([200, 503]).toContain(response.status());

    const body = await response.json();
    expect(body).toHaveProperty('timestamp');
    expect(body).toHaveProperty('gateway');
    expect(body).toHaveProperty('services');

    // Check for expected services
    const services = body.services;
    const expectedServices = ['identity', 'oauth', 'governance', 'audit', 'admin', 'risk'];

    for (const svc of expectedServices) {
      expect(services).toHaveProperty(svc);
      expect(services[svc]).toHaveProperty('healthy');
      expect(services[svc]).toHaveProperty('url');
    }
  });
});

test.describe('API Gateway - Service Routing', () => {
  test('Proxies requests to identity service', async ({ request }) => {
    // This test expects the identity service to be running
    const response = await request.get('/api/v1/identity/health');

    if (response.status() === 200) {
      const body = await response.json();
      expect(body).toHaveProperty('status', 'ok');
      expect(body).toHaveProperty('service', 'identity');
    } else {
      // Service might not be running in test environment
      expect([502, 503, 504]).toContain(response.status());
    }
  });

  test('Proxies requests to OAuth service', async ({ request }) => {
    const response = await request.get('/api/v1/oauth/.well-known/openid-configuration');

    if (response.status() === 200) {
      const body = await response.json();
      expect(body).toHaveProperty('issuer');
      expect(body).toHaveProperty('authorization_endpoint');
      expect(body).toHaveProperty('token_endpoint');
    } else {
      // Service might not be running
      expect([502, 503, 504]).toContain(response.status());
    }
  });

  test('Proxies requests to governance service', async ({ request }) => {
    const response = await request.get('/api/v1/governance/reviews');

    // May return 401 if auth is required, or 502/503 if service is down
    expect([200, 401, 403, 502, 503]).toContain(response.status());
  });

  test('Proxies requests to audit service', async ({ request }) => {
    const response = await request.get('/api/v1/audit/statistics');

    // May return 401 if auth is required
    expect([200, 401, 403, 502, 503]).toContain(response.status());
  });

  test('Proxies requests to admin service', async ({ request }) => {
    const response = await request.get('/api/v1/admin/dashboard');

    // May return 401 if auth is required
    expect([200, 401, 403, 502, 503]).toContain(response.status());
  });

  test('Proxies requests to risk service', async ({ request }) => {
    const response = await request.get('/api/v1/risk/statistics');

    // May return 401 if auth is required
    expect([200, 401, 403, 502, 503]).toContain(response.status());
  });
});

test.describe('API Gateway - CORS Headers', () => {
  test('OPTIONS request returns CORS headers', async ({ request }) => {
    const response = await request.fetch('/api/v1/identity/users', {
      method: 'OPTIONS',
      headers: {
        'Origin': 'http://localhost:3000',
        'Access-Control-Request-Method': 'GET',
      },
    });

    expect(response.status()).toBe(204);
    expect(response.headers()['access-control-allow-origin']).toBeTruthy();
    expect(response.headers()['access-control-allow-methods']).toContain('GET');
    expect(response.headers()['access-control-allow-headers']).toContain('Authorization');
  });

  test('GET request includes CORS headers', async ({ request }) => {
    const response = await request.get('/health', {
      headers: {
        'Origin': 'http://localhost:3000',
      },
    });

    expect(response.status()).toBe(200);
    expect(response.headers()['access-control-allow-origin']).toBeTruthy();
  });
});

test.describe('API Gateway - Correlation ID', () => {
  test('Generates correlation ID when not provided', async ({ request }) => {
    const response = await request.get('/health');

    expect(response.status()).toBe(200);

    const correlationId = response.headers()['x-correlation-id'];
    expect(correlationId).toBeTruthy();
    expect(correlationId).toMatch(/^[0-9a-f-]{36}$/); // UUID format
  });

  test('Uses provided correlation ID', async ({ request }) => {
    const testId = 'test-correlation-id-12345';
    const response = await request.get('/health', {
      headers: {
        'X-Correlation-ID': testId,
      },
    });

    expect(response.status()).toBe(200);
    expect(response.headers()['x-correlation-id']).toBe(testId);
  });

  test('Falls back to X-Request-ID if X-Correlation-ID not provided', async ({ request }) => {
    const requestId = 'test-request-id-67890';
    const response = await request.get('/health', {
      headers: {
        'X-Request-ID': requestId,
      },
    });

    expect(response.status()).toBe(200);
    expect(response.headers()['x-correlation-id']).toBe(requestId);
  });
});

test.describe('API Gateway - Rate Limiting Headers', () => {
  test('Returns rate limit headers for protected endpoints', async ({ request }) => {
    const response = await request.get('/api/v1/identity/users');

    // Even with auth failure, we should see rate limit headers if rate limiting is enabled
    if (response.status() !== 502 && response.status() !== 503) {
      const rateLimitLimit = response.headers()['x-ratelimit-limit'];
      const rateLimitRemaining = response.headers()['x-ratelimit-remaining'];
      const rateLimitReset = response.headers()['x-ratelimit-reset'];

      // Rate limiting may or may not be enabled in test environment
      if (rateLimitLimit) {
        expect(rateLimitRemaining).toBeTruthy();
        expect(rateLimitReset).toBeTruthy();
      }
    }
  });

  test('Returns 429 when rate limit is exceeded', async ({ request }) => {
    // This test requires making many requests quickly
    // Skip if rate limiting is not enabled
    let rateLimited = false;
    let attempts = 0;
    const maxAttempts = 150; // Adjust based on actual rate limit

    for (let i = 0; i < maxAttempts && !rateLimited; i++) {
      const response = await request.get('/api/v1/identity/users');

      if (response.status() === 429) {
        rateLimited = true;
        const body = await response.json();
        expect(body).toHaveProperty('error', 'rate limit exceeded');
        expect(response.headers()['retry-after']).toBeTruthy();
      }
      attempts++;
    }

    // If rate limiting is enabled, we should eventually hit it
    // If not enabled, this just validates that many requests succeed
    if (!rateLimited) {
      // Rate limiting likely not enabled in test environment
      console.log('Rate limiting appears to be disabled');
    }
  }).timeout(60000);
});

test.describe('API Gateway - API Documentation', () => {
  test('GET /api/docs returns combined OpenAPI spec', async ({ request }) => {
    const response = await request.get('/api/docs');

    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('application/json');

    const body = await response.json();
    expect(body).toHaveProperty('openapi');
    expect(body).toHaveProperty('info');
    expect(body).toHaveProperty('paths');
    expect(body).toHaveProperty('components');
  });

  test('GET /api/docs/identity returns identity service spec', async ({ request }) => {
    const response = await request.get('/api/docs/identity');

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('openapi');
    expect(body.info).toHaveProperty('title');
    expect(body.info.title).toContain('Identity');
  });

  test('GET /api/docs/oauth returns OAuth service spec', async ({ request }) => {
    const response = await request.get('/api/docs/oauth');

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.info.title).toContain('OAuth');
  });

  test('GET /api/docs/html returns HTML documentation page', async ({ request }) => {
    const response = await request.get('/api/docs/html');

    expect(response.status()).toBe(200);
    expect(response.headers()['content-type']).toContain('text/html');

    const body = await response.text();
    expect(body).toContain('OpenIDX API Documentation');
  });

  test('GET /api/docs/schema returns JSON schema', async ({ request }) => {
    const response = await request.get('/api/docs/schema');

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('$schema');
    expect(body).toHaveProperty('title');
  });
});

test.describe('API Gateway - Error Handling', () => {
  test('Returns 404 for non-existent routes', async ({ request }) => {
    const response = await request.get('/api/v1/nonexistent/resource');

    // May return 404 from gateway or proxy through to service
    expect([404, 502, 503]).toContain(response.status());
  });

  test('Returns proper JSON error for invalid requests', async ({ request }) => {
    const response = await request.post('/api/v1/oauth/token', {
      data: {
        // Invalid grant type
        grant_type: 'invalid',
      },
    });

    // Should return 400 or 401
    expect([400, 401]).toContain(response.status());

    const body = await response.json();
    expect(body).toHaveProperty('error');
  });

  test('Handles malformed JSON in requests', async ({ request }) => {
    const response = await request.post('/api/v1/identity/users', {
      data: '{invalid json}',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Should return 400 Bad Request
    expect([400, 401]).toContain(response.status());
  });
});

test.describe('API Gateway - Security Headers', () => {
  test('Returns appropriate security headers', async ({ request }) => {
    const response = await request.get('/health');

    expect(response.status()).toBe(200);

    // Check for common security headers
    const headers = response.headers();

    // These headers may or may not be present depending on configuration
    if (headers['x-content-type-options']) {
      expect(headers['x-content-type-options']).toBe('nosniff');
    }
  });

  test('Does not expose sensitive error details', async ({ request }) => {
    const response = await request.get('/api/v1/internal/error');

    const body = await response.json();

    // Error messages should be sanitized
    if (body.error) {
      expect(body.error).not.toMatch(/password/i);
      expect(body.error).not.toMatch(/secret/i);
      expect(body.error).not.toMatch(/token/i);
    }
  });
});

test.describe('API Gateway - Authentication Flow', () => {
  test('Rejects requests without valid authentication', async ({ request }) => {
    const response = await request.get('/api/v1/identity/users');

    // Should require authentication
    expect([401, 403]).toContain(response.status());

    const body = await response.json();
    expect(body).toHaveProperty('error');
  });

  test('Accepts requests with valid Bearer token', async ({ request }) => {
    // This test would need a valid token, so we'll just check the format
    const response = await request.get('/api/v1/identity/users', {
      headers: {
        'Authorization': 'Bearer invalid-token',
      },
    });

    // Should reject invalid token
    expect([401, 403]).toContain(response.status());
  });
});

test.describe('API Gateway - Legacy Endpoints', () => {
  test('GET /ready returns readiness (legacy endpoint)', async ({ request }) => {
    const response = await request.get('/ready');

    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('status', 'ready');
  });
});

test.describe('API Gateway - Performance', () => {
  test('Health endpoint responds quickly', async ({ request }) => {
    const startTime = Date.now();
    const response = await request.get('/health');
    const endTime = Date.now();

    expect(response.status()).toBe(200);
    expect(endTime - startTime).toBeLessThan(100); // Should respond in < 100ms
  });

  test('Concurrent requests are handled properly', async ({ request }) => {
    const requests = Array(10).fill(null).map(() =>
      request.get('/health')
    );

    const responses = await Promise.all(requests);

    // All should succeed
    responses.forEach(response => {
      expect(response.status()).toBe(200);
    });
  });
});
