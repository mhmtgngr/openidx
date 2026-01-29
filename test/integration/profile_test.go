//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserProfile(t *testing.T) {
	const username = "profile-test-user"
	const email = "profile-test@openidx.local"
	const password = "Profile@123"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	token := loginAndGetToken(t, username, password)
	require.NotEmpty(t, token)

	t.Run("get current user profile", func(t *testing.T) {
		status, body := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me", "", token)

		assert.Equal(t, 200, status)
		assert.Equal(t, "Integration", body["firstName"])
		assert.Equal(t, "Test", body["lastName"])
		assert.Equal(t, email, body["email"])
		assert.Equal(t, true, body["enabled"])
		assert.NotEmpty(t, body["createdAt"])
	})

	t.Run("update profile", func(t *testing.T) {
		updateData := `{
			"firstName": "Updated",
			"lastName": "Profile",
			"email": "` + email + `",
			"enabled": true
		}`

		status, body := apiRequest(t, "PUT", identityURL+"/api/v1/identity/users/me", updateData, token)

		assert.Equal(t, 200, status)
		assert.Equal(t, "Updated", body["firstName"])
		assert.Equal(t, "Profile", body["lastName"])
	})

	t.Run("profile reflects updates", func(t *testing.T) {
		status, body := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me", "", token)

		assert.Equal(t, 200, status)
		assert.Equal(t, "Updated", body["firstName"])
		assert.Equal(t, "Profile", body["lastName"])
	})

	t.Run("unauthenticated access rejected", func(t *testing.T) {
		status, _ := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me", "", "")
		assert.Equal(t, 401, status)
	})

	t.Run("invalid token rejected", func(t *testing.T) {
		status, _ := apiRequest(t, "GET", identityURL+"/api/v1/identity/users/me", "", "not-a-valid-jwt")
		assert.Equal(t, 401, status)
	})
}

func TestChangePassword(t *testing.T) {
	const username = "password-test-user"
	const email = "password-test@openidx.local"
	const password = "Original@123"
	const newPassword = "Changed@456"

	userID := createTestUser(t, username, email, password)
	defer deleteTestUser(t, userID)

	token := loginAndGetToken(t, username, password)
	require.NotEmpty(t, token)

	t.Run("change password with correct current password", func(t *testing.T) {
		data := `{"currentPassword":"` + password + `","newPassword":"` + newPassword + `"}`
		status, _ := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/change-password", data, token)
		assert.Equal(t, 200, status)
	})

	t.Run("can login with new password", func(t *testing.T) {
		newToken := loginAndGetToken(t, username, newPassword)
		assert.NotEmpty(t, newToken)
	})

	t.Run("wrong current password rejected", func(t *testing.T) {
		// Get a fresh token with the new password
		freshToken := loginAndGetToken(t, username, newPassword)

		data := `{"currentPassword":"wrong-password","newPassword":"anything"}`
		status, _ := apiRequest(t, "POST", identityURL+"/api/v1/identity/users/me/change-password", data, freshToken)
		assert.Equal(t, 400, status)
	})
}
