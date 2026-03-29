package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScreenLockCheck_Name(t *testing.T) {
	c := &ScreenLockCheck{}
	assert.Equal(t, "screen_lock", c.Name())
}

func TestScreenLockCheck_Run_NilParams(t *testing.T) {
	c := &ScreenLockCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestScreenLockCheck_Run_HasMessage(t *testing.T) {
	c := &ScreenLockCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Message)
}

func TestScreenLockCheck_Run_ScoreRange(t *testing.T) {
	c := &ScreenLockCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Score, float64(0))
	assert.LessOrEqual(t, result.Score, float64(1))
}

func TestScreenLockCheck_Run_FailHasRemediation(t *testing.T) {
	c := &ScreenLockCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	if result.Status == StatusFail {
		assert.NotEmpty(t, result.Remediation)
	}
}
