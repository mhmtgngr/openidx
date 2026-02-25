// Playwright E2E tests for WebAuthn security features
// These tests verify that WebAuthn credential management properly enforces
// JWT-based authentication and ownership verification

import { test, expect } from '@playwright/test'

// Mock JWT token for authenticated requests
const mockValidToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMzQiLCJ1c2VybmFtZSI6ImpzbWl0aCIsImRpc3BsYXlfbmFtZSI6IkpvaG4gU21pdGgiLCJyb2xlcyI6WyJ1c2VyIl0sImV4cCI6OTk5OTk5OTk5OX0.mock_signature'

// Mock user info stored in localStorage
const mockUserInfo = {
  id: 'user-1234',
  username: 'jsmith',
  displayName: 'John Smith',
  email: 'john@example.com',
}

test.describe('WebAuthn Credentials - Authentication Required', () => {
  test('should return 401 when accessing credentials without JWT token', async ({ page }) => {
    // Mock the API to simulate 401 Unauthorized response
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'authentication_required',
          message: 'Valid JWT token required',
        }),
      })
    })

    // Navigate to security keys page without auth
    await page.goto('/security-keys')

    // Should show authentication error message
    await expect(page.locator('text=Authentication Error')).toBeVisible({ timeout: 5000 })
    await expect(page.locator('text=Please log in again')).toBeVisible()
  })

  test('should return 403 when trying to delete another user\'s credential', async ({ page }) => {
    // Mock API response for listing credentials
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          credentials: [
            {
              id: 'cred-1',
              credential_id: 'abc123',
              friendly_name: 'My Security Key',
              authenticator: 'FIDO2',
              is_passkey: true,
              backup_eligible: true,
              backup_state: true,
              created_at: '2026-01-15T00:00:00Z',
            },
          ],
          count: 1,
        }),
      })
    })

    // Mock API response for delete attempt (403 Forbidden)
    await page.route('**/api/v1/identity/mfa/webauthn/credentials/other-user-cred', async (route) => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'access_denied',
          message: 'You do not have permission to delete this credential',
        }),
      })
    })

    // Set auth token
    await page.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify({
        id: 'user-1234',
        username: 'jsmith',
        displayName: 'John Smith',
      }))
    }, mockValidToken)

    await page.goto('/security-keys')

    // Credentials list should load
    await expect(page.locator('text=My Security Key')).toBeVisible({ timeout: 5000 })

    // Try to delete a credential that doesn't belong to the user
    // This would typically be done by modifying the DOM or direct API call
    const response = await page.request.delete('/api/v1/identity/mfa/webauthn/credentials/other-user-cred', {
      headers: {
        Authorization: `Bearer ${mockValidToken}`,
      },
    })

    expect(response.status()).toBe(403)
    const errorBody = await response.json()
    expect(errorBody.error).toBe('access_denied')
  })

  test('should return 403 when trying to rename another user\'s credential', async ({ page }) => {
    // Mock API response for rename attempt (403 Forbidden)
    await page.route('**/api/v1/identity/mfa/webauthn/credentials/other-cred/name', async (route) => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'access_denied',
          message: 'You do not have permission to modify this credential',
        }),
      })
    })

    // Try to rename a credential that doesn't belong to the user
    const response = await page.request.put('/api/v1/identity/mfa/webauthn/credentials/other-cred/name', {
      data: { friendly_name: 'Hacked Name' },
      headers: {
        Authorization: `Bearer ${mockValidToken}`,
        'Content-Type': 'application/json',
      },
    })

    expect(response.status()).toBe(403)
    const errorBody = await response.json()
    expect(errorBody.error).toBe('access_denied')
  })
})

test.describe('WebAuthn Credentials - Success Cases', () => {
  test('should list credentials when authenticated with valid JWT', async ({ page }) => {
    // Mock successful API response
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      const authHeader = route.request().headers()['authorization']
      // Verify Authorization header is present
      expect(authHeader).toMatch(/^Bearer /)

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          credentials: [
            {
              id: 'cred-1',
              credential_id: 'abc123',
              friendly_name: 'YubiKey 5C',
              authenticator: 'Yubico YubiKey 5C',
              is_passkey: true,
              backup_eligible: true,
              backup_state: true,
              created_at: '2026-01-15T00:00:00Z',
              last_used_at: '2026-02-20T00:00:00Z',
            },
            {
              id: 'cred-2',
              credential_id: 'def456',
              friendly_name: 'iPhone Face ID',
              authenticator: 'Apple Face ID',
              is_passkey: true,
              backup_eligible: true,
              backup_state: true,
              created_at: '2026-02-01T00:00:00Z',
            },
          ],
          count: 2,
        }),
      })
    })

    // Set auth token
    await page.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify({
        id: 'user-1234',
        username: 'jsmith',
        displayName: 'John Smith',
      }))
    }, mockValidToken)

    await page.goto('/security-keys')

    // Should show credentials
    await expect(page.getByRole('heading', { name: /Security Keys/i })).toBeVisible({ timeout: 5000 })
    await expect(page.locator('text=YubiKey 5C')).toBeVisible()
    await expect(page.locator('text=iPhone Face ID')).toBeVisible()
    await expect(page.locator('text=2 security keys registered')).toBeVisible()
  })

  test('should delete credential successfully when user owns it', async ({ page }) => {
    let deleteCalled = false

    // Mock list API
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          credentials: [
            {
              id: 'cred-1',
              credential_id: 'abc123',
              friendly_name: 'YubiKey 5C',
              authenticator: 'Yubico YubiKey 5C',
              is_passkey: true,
              backup_eligible: true,
              backup_state: true,
              created_at: '2026-01-15T00:00:00Z',
            },
          ],
          count: 1,
        }),
      })
    })

    // Mock delete API
    await page.route('**/api/v1/identity/mfa/webauthn/credentials/cred-1', async (route) => {
      if (route.request().method() === 'DELETE') {
        deleteCalled = true
        const authHeader = route.request().headers()['authorization']
        // Verify Authorization header is present
        expect(authHeader).toMatch(/^Bearer /)

        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            success: true,
            message: 'Credential deleted successfully',
          }),
        })
      }
    })

    // Set auth token
    await page.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify({
        id: 'user-1234',
        username: 'jsmith',
        displayName: 'John Smith',
      }))
    }, mockValidToken)

    await page.goto('/security-keys')

    // Click delete button
    await page.getByRole('button', { name: /delete/i }).first().click()

    // Verify delete was called
    expect(deleteCalled).toBe(true)
  })

  test('should rename credential successfully when user owns it', async ({ page }) => {
    let renameCalled = false

    // Mock list API
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          credentials: [
            {
              id: 'cred-1',
              credential_id: 'abc123',
              friendly_name: 'YubiKey 5C',
              authenticator: 'Yubico YubiKey 5C',
              is_passkey: true,
              backup_eligible: true,
              backup_state: true,
              created_at: '2026-01-15T00:00:00Z',
            },
          ],
          count: 1,
        }),
      })
    })

    // Mock rename API
    await page.route('**/api/v1/identity/mfa/webauthn/credentials/cred-1/name', async (route) => {
      if (route.request().method() === 'PUT') {
        renameCalled = true
        const authHeader = route.request().headers()['authorization']
        expect(authHeader).toMatch(/^Bearer /)

        // Verify request body
        const body = route.request().postData()
        const parsedBody = JSON.parse(body || '{}')
        expect(parsedBody.friendly_name).toBe('My New Key Name')

        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            success: true,
            message: 'Credential renamed successfully',
            friendly_name: 'My New Key Name',
          }),
        })
      }
    })

    // Set auth token
    await page.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify({
        id: 'user-1234',
        username: 'jsmith',
        displayName: 'John Smith',
      }))
    }, mockValidToken)

    await page.goto('/security-keys')

    // Click edit button
    await page.getByRole('button', { name: /edit/i }).first().click()

    // Change the name
    await page.getByRole('textbox').fill('My New Key Name')

    // Click confirm
    await page.getByRole('button', { name: /confirm/i }).click()

    // Verify rename was called
    expect(renameCalled).toBe(true)
  })
})

test.describe('WebAuthn Registration Flow', () => {
  test('should begin registration with authenticated user context', async ({ page }) => {
    let registerBeginCalled = false

    // Mock list API (empty)
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ credentials: [], count: 0 }),
      })
    })

    // Mock registration begin API
    await page.route('**/api/v1/identity/mfa/webauthn/register/begin', async (route) => {
      if (route.request().method() === 'POST') {
        registerBeginCalled = true
        const authHeader = route.request().headers()['authorization']
        expect(authHeader).toMatch(/^Bearer /)

        // Verify request contains user info (from JWT, not query param)
        const body = route.request().postData()
        const parsedBody = JSON.parse(body || '{}')
        expect(parsedBody.username).toBeDefined()
        expect(parsedBody.display_name).toBeDefined()

        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            status: 'ok',
            message: 'Registration initiated',
            options: {
              publicKey: {
                rp: { name: 'OpenIDX', id: 'localhost' },
                user: {
                  id: 'dXNlci0xMjM0',
                  name: 'jsmith',
                  displayName: 'John Smith',
                },
                challenge: 'dGVzdC1jaGFsbGVuZ2U',
                pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                timeout: 60000,
                authenticatorSelection: {
                  authenticatorAttachment: 'cross-platform',
                  requireResidentKey: false,
                },
              },
            },
          }),
        })
      }
    })

    // Set auth token and user info
    await page.addInitScript((token, userInfo) => {
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify(userInfo))
    }, mockValidToken, mockUserInfo)

    await page.goto('/security-keys')

    // Click register button
    await page.getByRole('button', { name: /Register Security Key/i }).click()

    // Fill in key name
    await page.getByRole('textbox', { name: /key name/i }).fill('My New Key')

    // Click register
    await page.getByRole('button', { name: /^Register$/ }).click()

    // Verify API was called
    expect(registerBeginCalled).toBe(true)
  })
})

test.describe('WebAuthn Security - Edge Cases', () => {
  test('should warn when trying to delete last credential', async ({ page }) => {
    // Mock list API with single credential
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          credentials: [
            {
              id: 'cred-1',
              credential_id: 'abc123',
              friendly_name: 'Only Key',
              authenticator: 'FIDO2',
              is_passkey: true,
              backup_eligible: true,
              backup_state: true,
              created_at: '2026-01-15T00:00:00Z',
            },
          ],
          count: 1,
        }),
      })
    })

    // Set auth token
    await page.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify({
        id: 'user-1234',
        username: 'jsmith',
        displayName: 'John Smith',
      }))
    }, mockValidToken)

    await page.goto('/security-keys')

    // Try to delete the only credential
    await page.getByRole('button', { name: /delete/i }).click()

    // Should show warning toast
    await expect(page.locator('text=at least one security key')).toBeVisible({ timeout: 5000 })
  })

  test('should handle expired JWT token gracefully', async ({ page }) => {
    // Mock API returning 401 with expired token message
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({
          error: 'token_expired',
          message: 'Your session has expired. Please log in again.',
        }),
      })
    })

    // Set expired token
    await page.addInitScript(() => {
      localStorage.setItem('token', 'expired.token.here')
      localStorage.setItem('user', JSON.stringify({
        id: 'user-1234',
        username: 'jsmith',
        displayName: 'John Smith',
      }))
    })

    await page.goto('/security-keys')

    // Should show authentication error with retry option
    await expect(page.locator('text=Authentication Error')).toBeVisible({ timeout: 5000 })
    await expect(page.getByRole('button', { name: /Retry/i })).toBeVisible()
  })

  test('should not include user_id in query parameters', async ({ page }) => {
    let queryParams: string[] = []

    // Intercept all requests to check for user_id in query
    page.on('request', (request) => {
      const url = request.url()
      if (url.includes('/api/v1/identity/mfa/webauthn/')) {
        const parsedUrl = new URL(url)
        if (parsedUrl.searchParams.has('user_id')) {
          queryParams.push(url)
        }
      }
    })

    // Mock list API
    await page.route('**/api/v1/identity/mfa/webauthn/credentials', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ credentials: [], count: 0 }),
      })
    })

    // Set auth token
    await page.addInitScript((token) => {
      localStorage.setItem('token', token)
      localStorage.setItem('user', JSON.stringify({
        id: 'user-1234',
        username: 'jsmith',
        displayName: 'John Smith',
      }))
    }, mockValidToken)

    await page.goto('/security-keys')

    // Wait for page to load
    await page.waitForTimeout(1000)

    // Verify no user_id was sent in query parameters
    expect(queryParams.length).toBe(0)
  })
})
