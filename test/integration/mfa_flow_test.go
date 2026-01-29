//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMFASetupFlow(t *testing.T) {
	const username = "mfa-test-user"
	const email = "mfa-test@openidx.local"
	const password = "MfaTest@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	token := loginAndGetToken(t, username, password)
	require.NotEmpty(t, token)

	t.Run("setup returns secret and QR URL", func(t *testing.T) {
		status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/setup", "", token)

		assert.Equal(t, 200, status)
		assert.NotEmpty(t, body["secret"], "MFA setup should return a secret")
		assert.NotEmpty(t, body["qrCodeUrl"], "MFA setup should return a QR code URL")

		qrURL, _ := body["qrCodeUrl"].(string)
		assert.Contains(t, qrURL, "otpauth://totp/", "QR URL should be an otpauth URI")
		assert.Contains(t, qrURL, "OpenIDX", "QR URL should contain issuer name")
	})

	t.Run("enable with invalid code is rejected", func(t *testing.T) {
		// First call setup to prime the Redis cache
		apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/setup", "", token)

		status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/enable", `{"code":"000000"}`, token)
		assert.Equal(t, 400, status)
		assert.Contains(t, body["error"], "invalid")
	})

	t.Run("enable without setup is rejected", func(t *testing.T) {
		// Create a fresh user that hasn't called setup
		freshUser := createTestUser(t, "mfa-fresh-user", "mfa-fresh@openidx.local", password)
		defer deleteTestUser(t, freshUser)

		freshToken := loginAndGetToken(t, "mfa-fresh-user", password)
		status, body := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/enable", `{"code":"123456"}`, freshToken)

		assert.Equal(t, 400, status)
		assert.Contains(t, body["error"], "setup")
	})
}

func TestMFAProfileStatus(t *testing.T) {
	const username = "mfa-status-user"
	const email = "mfa-status@openidx.local"
	const password = "MfaStatus@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	token := loginAndGetToken(t, username, password)
	require.NotEmpty(t, token)

	// Profile should show MFA disabled initially
	status, body := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me", "", token)
	assert.Equal(t, 200, status)

	mfaEnabled, ok := body["mfaEnabled"].(bool)
	assert.True(t, ok, "mfaEnabled should be a boolean")
	assert.False(t, mfaEnabled, "MFA should be disabled by default")

	mfaMethods, ok := body["mfaMethods"].([]interface{})
	assert.True(t, ok, "mfaMethods should be an array")
	assert.Empty(t, mfaMethods, "mfaMethods should be empty when MFA is disabled")
}

func TestMFADisableWithoutEnroll(t *testing.T) {
	const username = "mfa-disable-user"
	const email = "mfa-disable@openidx.local"
	const password = "MfaDisable@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	token := loginAndGetToken(t, username, password)

	// Disabling MFA when not enrolled should still succeed (idempotent)
	status, _ := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/mfa/disable", "", token)
	assert.Equal(t, 200, status)
}
