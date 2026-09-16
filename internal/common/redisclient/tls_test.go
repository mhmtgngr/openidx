package redisclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildRedisTLSConfig tests buildTLSConfig function behavior
func TestBuildRedisTLSConfig(t *testing.T) {
	t.Run("TLS disabled returns nil", func(t *testing.T) {
		cfg := Config{
			TLSEnabled: false,
		}
		tlsCfg, err := buildTLSConfig(cfg)
		require.NoError(t, err)
		assert.Nil(t, tlsCfg)
	})
}

// TestCACertReadFailure is the Redis half of what was database's TestReadCACert;
// the Elasticsearch half stayed with the Elasticsearch client.
func TestCACertReadFailure(t *testing.T) {
	cfg := Config{
		TLSEnabled: true,
		TLSCACert:  "/nonexistent/path/to/ca.crt",
	}
	_, err := buildTLSConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CA cert")
}
