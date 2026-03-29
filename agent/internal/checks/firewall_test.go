package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFirewallCheck_Name(t *testing.T) {
	c := &FirewallCheck{}
	assert.Equal(t, "firewall", c.Name())
}

func TestFirewallCheck_Run_NilParams(t *testing.T) {
	c := &FirewallCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestFirewallCheck_Run_HasMessage(t *testing.T) {
	c := &FirewallCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Message)
}

func TestFirewallCheck_Run_ScoreRange(t *testing.T) {
	c := &FirewallCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Score, float64(0))
	assert.LessOrEqual(t, result.Score, float64(1))
}

func TestFirewallCheck_Run_FailHasRemediation(t *testing.T) {
	c := &FirewallCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	if result.Status == StatusFail {
		assert.NotEmpty(t, result.Remediation)
	}
}
