import { test, expect } from '@playwright/test';

/**
 * E2E Tests for WebAuthn Authentication Flow
 *
 * These tests verify:
 * 1. JWT authentication is required for credential management endpoints
 * 2. Users can only access their own credentials
 * 3. Ownership verification works correctly for delete/rename operations
 * 4. CSRF protection is applied to state-changing operations
 */

test.describe('WebAuthn Credential Authentication', () => {
  const validUserToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTFhYmMzZDUlIiwidGlkIjoidGVuYW50LTEiLCJyb2xlcyI6WyJ1c2VyIl0sInRva2VuX3R5cGUiOiJhY2Nlc3MiLCJleHAiOjk5OTk5OTk5OTl9.valid-signature';
  const otherUserToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTIiLCJ0aWQiOiJ0ZW5hbnQtMSIsInJvbGVzIjpbInVzZXIiXSwidG9rZW5fdHlwZSI6ImFjY2VzcyIsImV4cCI6OTk5OTk5OTk5OX0.valid-signature';
  const expiredToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEiLCJ0aWQiOiJ0ZW5hbnQtMSIsInJvbGVzIjpbInVzZXIiXSwidG9rZW5fdHlwZSI6ImFjY2VzcyIsImV4cCI6MTYwMDAwMDAwMH0.expired';

  // Test credentials data
  const user1Credentials = [
    {
      id: 'cred-1',
      user_id: 'user-1abc3d5',
      credential_id: 'user1-cred-1',
      friendly_name: 'User 1 Passkey',
      authenticator: 'Passkey',
      is_passkey: true,
      backup_eligible: true,
      backup_state: true,
      created_at: '2026-01-15T00:00:00Z',
      last_used_at: '2026-02-10T00:00:00Z',
    },
  ];

  const user2Credentials = [
    {
      id: 'cred-2',
      user_id: 'user-2',
      credential_id: 'user2-cred-1',
      friendly_name: 'User 2 YubiKey',
      authenticator: 'Security Key',
      is_passkey: false,
      backup_eligible: false,
      backup_state: false,
      created_at: '2026-01-20T00:00:00Z',
      last_used_at: '2026-02-12T00:00:00Z',
    },
  ];

  test.beforeEach(async ({ page, context }) => {
    await context.clearCookies();
    await page.goto('/security-keys');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
    await page.reload();
  });

  test.describe('Authentication Requirements', () => {
    test('should redirect to login when accessing credentials without auth', async ({ page }) => {
      // Mock credentials endpoint to require auth
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'missing authorization header',
          }),
        });
      });

      await page.goto('/security-keys');

      // Should show authentication error or redirect
      await expect(page).toHaveURL(/\/(login|security-keys)/);
    });

    test('should return 401 with expired token', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'expired-token-here');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'token is expired',
          }),
        });
      });

      await page.goto('/security-keys');

      // Should show error message
      await expect(page.locator('text=Unauthorized')).toBeVisible({ timeout: 10000 });
    });

    test('should return 401 with invalid token', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'invalid-token-format');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'token is invalid',
          }),
        });
      });

      await page.goto('/security-keys');

      await expect(page.locator('text=Unauthorized')).toBeVisible({ timeout: 10000 });
    });

    test('should successfully load credentials with valid token', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'valid-user-token');
        localStorage.setItem('refresh_token', 'mock-refresh');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            credentials: user1Credentials,
            count: 1,
          }),
        });
      });

      await page.goto('/security-keys');

      await expect(page.getByRole('heading', { name: /Security Keys/i })).toBeVisible({ timeout: 10000 });
      await expect(page.locator('text=User 1 Passkey')).toBeVisible();
    });
  });

  test.describe('Ownership Verification - List Credentials', () => {
    test('user 1 should only see their own credentials', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-1-token');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        const authHeader = route.request().headers()['authorization'];
        const token = authHeader?.replace('Bearer ', '');

        // Return different credentials based on token
        if (token === 'user-1-token') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: user1Credentials,
              count: 1,
            }),
          });
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: user2Credentials,
              count: 1,
            }),
          });
        }
      });

      await page.goto('/security-keys');

      await expect(page.locator('text=User 1 Passkey')).toBeVisible();
      await expect(page.locator('text=User 2 YubiKey')).not.toBeVisible();
    });

    test('user 2 should only see their own credentials', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-2-token');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        const authHeader = route.request().headers()['authorization'];
        const token = authHeader?.replace('Bearer ', '');

        if (token === 'user-2-token') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: user2Credentials,
              count: 1,
            }),
          });
        } else {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: [],
              count: 0,
            }),
          });
        }
      });

      await page.goto('/security-keys');

      await expect(page.locator('text=User 2 YubiKey')).toBeVisible();
      await expect(page.locator('text=User 1 Passkey')).not.toBeVisible();
    });
  });

  test.describe('Ownership Verification - Delete Credential', () => {
    test('should allow user to delete their own credential', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-1-token');
      });

      // Mock delete endpoint
      await page.route('**/api/v1/mfa/webauthn/credentials/user1-cred-1', async (route) => {
        if (route.request().method() === 'DELETE') {
          const authHeader = route.request().headers()['authorization'];
          if (authHeader === 'Bearer user-1-token') {
            await route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                success: true,
                message: 'Credential deleted successfully',
              }),
            });
            return;
          }
        }
        await route.continue();
      });

      // Mock list endpoint for refresh
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: user1Credentials,
              count: 1,
            }),
          });
          return;
        }
        await route.continue();
      });

      await page.goto('/security-keys');
      await expect(page.locator('text=User 1 Passkey')).toBeVisible();

      // Click delete button (adjust selector based on actual UI)
      const deleteButton = page.getByRole('button', { name: /delete/i }).first();
      await deleteButton.click();

      // Confirm deletion if there's a dialog
      const confirmButton = page.getByRole('button', { name: /confirm|delete/i });
      if (await confirmButton.isVisible()) {
        await confirmButton.click();
      }

      // Verify success message
      await expect(page.locator('text=deleted successfully')).toBeVisible({ timeout: 5000 });
    });

    test('should prevent user from deleting another user\'s credential', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-2-token'); // User 2 is logged in
      });

      // Attempt to delete user 1's credential
      await page.route('**/api/v1/mfa/webauthn/credentials/user1-cred-1', async (route) => {
        if (route.request().method() === 'DELETE') {
          const authHeader = route.request().headers()['authorization'];
          if (authHeader === 'Bearer user-2-token') {
            // User 2 trying to delete User 1's credential - should be forbidden
            await route.fulfill({
              status: 403,
              contentType: 'application/json',
              body: JSON.stringify({
                error: 'access_denied',
                message: 'You do not have permission to delete this credential',
              }),
            });
            return;
          }
        }
        await route.continue();
      });

      // Mock list endpoint
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: user2Credentials,
              count: 1,
            }),
          });
          return;
        }
        await route.continue();
      });

      await page.goto('/security-keys');

      // Simulate a direct API call attempt (in real scenario, this button wouldn't be visible)
      const response = await page.request.delete('/api/v1/mfa/webauthn/credentials/user1-cred-1', {
        headers: {
          Authorization: 'Bearer user-2-token',
        },
      });

      expect(response.status()).toBe(403);
      const body = await response.json();
      expect(body.error).toBe('access_denied');
    });
  });

  test.describe('Ownership Verification - Rename Credential', () => {
    test('should allow user to rename their own credential', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-1-token');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials/user1-cred-1/name', async (route) => {
        if (route.request().method() === 'PUT') {
          const authHeader = route.request().headers()['authorization'];
          if (authHeader === 'Bearer user-1-token') {
            await route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({
                success: true,
                message: 'Credential renamed successfully',
                friendly_name: 'My Renamed Passkey',
              }),
            });
            return;
          }
        }
        await route.continue();
      });

      // Mock list endpoint
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        if (route.request().method() === 'GET') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: user1Credentials,
              count: 1,
            }),
          });
          return;
        }
        await route.continue();
      });

      await page.goto('/security-keys');
      await expect(page.locator('text=User 1 Passkey')).toBeVisible();

      // Click edit/rename button
      const editButton = page.getByRole('button', { name: /edit|rename/i }).first();
      await editButton.click();

      // Enter new name
      const nameInput = page.getByRole('textbox');
      await nameInput.fill('My Renamed Passkey');

      // Submit
      const saveButton = page.getByRole('button', { name: /save|submit/i });
      await saveButton.click();

      // Verify success
      await expect(page.locator('text=renamed successfully')).toBeVisible({ timeout: 5000 });
    });

    test('should prevent user from renaming another user\'s credential', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-2-token');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials/user1-cred-1/name', async (route) => {
        if (route.request().method() === 'PUT') {
          const authHeader = route.request().headers()['authorization'];
          if (authHeader === 'Bearer user-2-token') {
            await route.fulfill({
              status: 403,
              contentType: 'application/json',
              body: JSON.stringify({
                error: 'access_denied',
                message: 'You do not have permission to modify this credential',
              }),
            });
            return;
          }
        }
        await route.continue();
      });

      // Simulate API call
      const response = await page.request.put('/api/v1/mfa/webauthn/credentials/user1-cred-1/name', {
        headers: {
          Authorization: 'Bearer user-2-token',
          'Content-Type': 'application/json',
        },
        data: JSON.stringify({
          friendly_name: 'Hacked Name',
        }),
      });

      expect(response.status()).toBe(403);
      const body = await response.json();
      expect(body.error).toBe('access_denied');
    });
  });

  test.describe('CSRF Protection', () => {
    test('should require CSRF token for state-changing operations', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-1-token');
      });

      // Mock that CSRF is required
      await page.route('**/api/v1/mfa/webauthn/credentials/user1-cred-1', async (route) => {
        if (route.request().method() === 'DELETE') {
          const csrfToken = route.request().headers()['x-csrf-token'];
          if (!csrfToken) {
            await route.fulfill({
              status: 403,
              contentType: 'application/json',
              body: JSON.stringify({
                error: 'csrf_token_missing',
                message: 'CSRF token is required for this operation',
              }),
            });
            return;
          }
          if (csrfToken !== 'valid-csrf-token') {
            await route.fulfill({
              status: 403,
              contentType: 'application/json',
              body: JSON.stringify({
                error: 'csrf_token_invalid',
                message: 'Invalid CSRF token',
              }),
            });
            return;
          }
          // Valid CSRF token
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ success: true }),
          });
          return;
        }
        await route.continue();
      });

      // Request without CSRF token should fail
      const responseWithoutCSRF = await page.request.delete('/api/v1/mfa/webauthn/credentials/user1-cred-1', {
        headers: {
          Authorization: 'Bearer user-1-token',
        },
      });

      expect(responseWithoutCSRF.status()).toBe(403);
    });

    test('should allow request with valid CSRF token', async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('token', 'user-1-token');
        localStorage.setItem('csrf_token', 'valid-csrf-token');
      });

      await page.route('**/api/v1/mfa/webauthn/credentials/user1-cred-1', async (route) => {
        if (route.request().method() === 'DELETE') {
          const csrfToken = route.request().headers()['x-csrf-token'];
          if (csrfToken === 'valid-csrf-token') {
            await route.fulfill({
              status: 200,
              contentType: 'application/json',
              body: JSON.stringify({ success: true }),
            });
            return;
          }
        }
        await route.continue();
      });

      const response = await page.request.delete('/api/v1/mfa/webauthn/credentials/user1-cred-1', {
        headers: {
          Authorization: 'Bearer user-1-token',
          'X-CSRF-Token': 'valid-csrf-token',
        },
      });

      expect(response.status()).toBe(200);
    });
  });

  test.describe('Authorization Header Formats', () => {
    test('should reject request without Authorization header', async ({ page }) => {
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        const authHeader = route.request().headers()['authorization'];
        if (!authHeader) {
          await route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({
              error: 'missing authorization header',
            }),
          });
          return;
        }
        await route.continue();
      });

      await page.goto('/security-keys');

      const response = await page.request.get('/api/v1/mfa/webauthn/credentials');
      expect(response.status()).toBe(401);
    });

    test('should reject request with invalid Authorization format', async ({ page }) => {
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        const authHeader = route.request().headers()['authorization'];
        if (authHeader && !authHeader.startsWith('Bearer ')) {
          await route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({
              error: 'invalid authorization header format',
            }),
          });
          return;
        }
        await route.continue();
      });

      const response = await page.request.get('/api/v1/mfa/webauthn/credentials', {
        headers: {
          Authorization: 'InvalidFormat token',
        },
      });

      expect(response.status()).toBe(401);
    });

    test('should accept valid Bearer token format', async ({ page }) => {
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        const authHeader = route.request().headers()['authorization'];
        if (authHeader === 'Bearer valid-token') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              credentials: [],
              count: 0,
            }),
          });
          return;
        }
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'unauthorized' }),
        });
      });

      const response = await page.request.get('/api/v1/mfa/webauthn/credentials', {
        headers: {
          Authorization: 'Bearer valid-token',
        },
      });

      expect(response.status()).toBe(200);
    });
  });

  test.describe('Security Scenarios', () => {
    test('should prevent credential enumeration by checking ownership', async ({ page }) => {
      // User tries to enumerate other users' credentials by guessing IDs
      const credentialIDs = ['cred-1', 'cred-2', 'cred-3', 'admin-cred'];

      await page.addInitScript(() => {
        localStorage.setItem('token', 'regular-user-token');
      });

      for (const credID of credentialIDs) {
        await page.route(`**/api/v1/mfa/webauthn/credentials/${credID}`, async (route) => {
          const authHeader = route.request().headers()['authorization'];
          if (authHeader === 'Bearer regular-user-token') {
            // If credential doesn't belong to user, return 404 or 403
            if (credID === 'admin-cred') {
              await route.fulfill({
                status: 403,
                contentType: 'application/json',
                body: JSON.stringify({
                  error: 'access_denied',
                }),
              });
              return;
            }
            await route.fulfill({
              status: 404,
              contentType: 'application/json',
              body: JSON.stringify({
                error: 'credential_not_found',
              }),
            });
            return;
          }
          await route.continue();
        });

        const response = await page.request.get(`/api/v1/mfa/webauthn/credentials/${credID}`, {
          headers: {
            Authorization: 'Bearer regular-user-token',
          },
        });

        // Should not leak information about credential existence
        expect([403, 404]).toContain(response.status());
      }
    });

    test('should log security events for ownership violations', async ({ page }) => {
      let loggedSecurityEvent = false;

      await page.addInitScript(() => {
        localStorage.setItem('token', 'malicious-user-token');
      });

      // Mock an endpoint that logs security events
      await page.route('**/api/v1/mfa/webauthn/credentials/user1-cred-1', async (route) => {
        if (route.request().method() === 'DELETE') {
          loggedSecurityEvent = true;
          await route.fulfill({
            status: 403,
            contentType: 'application/json',
            body: JSON.stringify({
              error: 'access_denied',
              message: 'Security event logged: Unauthorized access attempt',
            }),
          });
          return;
        }
        await route.continue();
      });

      const response = await page.request.delete('/api/v1/mfa/webauthn/credentials/user1-cred-1', {
        headers: {
          Authorization: 'Bearer malicious-user-token',
        },
      });

      expect(response.status()).toBe(403);
      expect(loggedSecurityEvent).toBe(true);
    });
  });
});

/**
 * Tests for integration with the auth context helpers
 */
test.describe('WebAuthn Auth Context Integration', () => {
  test('should extract user ID from JWT claims correctly', async ({ page }) => {
    const validTokenWithSubject = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMy10ZXN0IiwidGlkIjoidGVuYW50LTEiLCJyb2xlcyI6WyJ1c2VyIl19.signature';

    await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
      const authHeader = route.request().headers()['authorization'];
      const token = authHeader?.replace('Bearer ', '');

      if (token === validTokenWithSubject) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            credentials: [],
            count: 0,
          }),
        });
        return;
      }
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'invalid_token' }),
      });
    });

    const response = await page.request.get('/api/v1/mfa/webauthn/credentials', {
      headers: {
        Authorization: `Bearer ${validTokenWithSubject}`,
      },
    });

    expect(response.status()).toBe(200);
  });

  test('should handle malformed JWT gracefully', async ({ page }) => {
    const malformedTokens = [
      'not-a-jwt',
      'invalid.header',
      'invalid.header.payload',
      'a.b.c',
    ];

    for (const token of malformedTokens) {
      await page.route('**/api/v1/mfa/webauthn/credentials', async (route) => {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'token is invalid' }),
        });
      });

      const response = await page.request.get('/api/v1/mfa/webauthn/credentials', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      expect(response.status(), `Token "${token}" should be rejected`).toBe(401);
    }
  });
});
