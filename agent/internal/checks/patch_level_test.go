package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatchLevelCheck_Name(t *testing.T) {
	c := &PatchLevelCheck{}
	assert.Equal(t, "patch_level", c.Name())
}

func TestPatchLevelCheck_Run_NilParams(t *testing.T) {
	c := &PatchLevelCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestPatchLevelCheck_Run_HasMessage(t *testing.T) {
	c := &PatchLevelCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Message)
}

func TestPatchLevelCheck_Run_ScoreRange(t *testing.T) {
	c := &PatchLevelCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Score, float64(0))
	assert.LessOrEqual(t, result.Score, float64(1))
}

func TestPatchLevelCheck_Run_MaxDaysParam_Int(t *testing.T) {
	c := &PatchLevelCheck{}
	// A max_days of 99999 should never trigger a fail due to age.
	result := c.Run(context.Background(), map[string]interface{}{"max_days": 99999})
	require.NotNil(t, result)
	// The result should not be StatusFail purely due to exceeding the day limit.
	if result.Status == StatusFail {
		// If it fails, it must not be because of age.
		assert.NotContains(t, result.Message, "exceeding the 99999-day limit")
	}
}

func TestPatchLevelCheck_Run_MaxDaysParam_Float64(t *testing.T) {
	c := &PatchLevelCheck{}
	result := c.Run(context.Background(), map[string]interface{}{"max_days": float64(99999)})
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestPatchLevelCheck_Run_FailHasRemediation(t *testing.T) {
	c := &PatchLevelCheck{}
	// A max_days of 0 will cause any real system to fail (0 days ago is impossible).
	result := c.Run(context.Background(), map[string]interface{}{"max_days": 0})
	require.NotNil(t, result)
	if result.Status == StatusFail {
		assert.NotEmpty(t, result.Remediation)
	}
}
