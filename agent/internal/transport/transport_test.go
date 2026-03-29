package transport

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestClient_ImplementsTransport(t *testing.T) {
	var _ Transport = (*Client)(nil)
	assert.True(t, true, "Client implements Transport interface")
}
