package jwksverify

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRSAPublicKey(t *testing.T) {
	t.Run("Valid RSA public key", func(t *testing.T) {
		// Example valid base64url encoded n and e values
		// These are simplified for testing - real values would be longer
		n := "xGOr-H7A1G7YPl6_HvU6pZsJPqaLkTKcFnEpKl7R6CQd5k9qzGJcEcQvN7JDQQ"
		e := "AQAB" // Standard RSA exponent (65537)

		key, err := parseRSAPublicKey(n, e)

		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.NotNil(t, key.N)
		assert.Equal(t, 65537, key.E)
	})

	t.Run("Invalid base64 n value", func(t *testing.T) {
		n := "invalid!!!base64"
		e := "AQAB"

		key, err := parseRSAPublicKey(n, e)

		assert.Error(t, err)
		assert.Nil(t, key)
	})

	t.Run("Invalid base64 e value", func(t *testing.T) {
		n := "xGOr-H7A1G7YPl6_HvU6pZsJPqaLkTKcFnEpKl7R6CQd5k9qzGJcEcQvN7JDQQ"
		e := "invalid!!!"

		key, err := parseRSAPublicKey(n, e)

		assert.Error(t, err)
		assert.Nil(t, key)
	})
}
