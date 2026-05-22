package transport

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClient_ImplementsTransport(t *testing.T) {
	var _ Transport = (*Client)(nil)
	assert.True(t, true, "Client implements Transport interface")
}

func TestZitiClient_ImplementsTransport(t *testing.T) {
	var _ Transport = (*ZitiClient)(nil)
}
