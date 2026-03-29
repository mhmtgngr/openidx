package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrityCheck_Name(t *testing.T) {
	c := &IntegrityCheck{}
	assert.Equal(t, "integrity", c.Name())
}

func TestIntegrityCheck_Run_NilParams(t *testing.T) {
	c := &IntegrityCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestIntegrityCheck_Run_HasMessage(t *testing.T) {
	c := &IntegrityCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Message)
}

func TestIntegrityCheck_Run_ScoreRange(t *testing.T) {
	c := &IntegrityCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Score, float64(0))
	assert.LessOrEqual(t, result.Score, float64(1))
}

func TestIntegrityCheck_Run_FailHasRemediation(t *testing.T) {
	c := &IntegrityCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	if result.Status == StatusFail {
		assert.NotEmpty(t, result.Remediation)
	}
}
