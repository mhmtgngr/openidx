package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAntivirusCheck_Name(t *testing.T) {
	c := &AntivirusCheck{}
	assert.Equal(t, "antivirus", c.Name())
}

func TestAntivirusCheck_Run_NilParams(t *testing.T) {
	c := &AntivirusCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestAntivirusCheck_Run_HasMessage(t *testing.T) {
	c := &AntivirusCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Message)
}

func TestAntivirusCheck_Run_ScoreRange(t *testing.T) {
	c := &AntivirusCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Score, float64(0))
	assert.LessOrEqual(t, result.Score, float64(1))
}

func TestAntivirusCheck_Run_FailHasRemediation(t *testing.T) {
	c := &AntivirusCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	if result.Status == StatusFail {
		assert.NotEmpty(t, result.Remediation)
	}
}
