package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSVersionCheck_Name(t *testing.T) {
	c := &OSVersionCheck{}
	assert.Equal(t, "os_version", c.Name())
}

func TestOSVersionCheck_Run_NilParams(t *testing.T) {
	c := &OSVersionCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	// Should not crash and should return a valid status.
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
	assert.NotNil(t, result.Details)
	assert.NotEmpty(t, result.Details["os"])
	assert.NotEmpty(t, result.Details["arch"])
}

func TestOSVersionCheck_Run_MinVersionVeryLow(t *testing.T) {
	// "0.0.1" is far below any real kernel version, so the check must pass.
	c := &OSVersionCheck{}
	params := map[string]interface{}{
		"min_version": "0.0.1",
	}
	result := c.Run(context.Background(), params)
	require.NotNil(t, result)
	assert.Equal(t, StatusPass, result.Status)
	assert.Equal(t, 1.0, result.Score)
}

func TestOSVersionCheck_Run_MinVersionVeryHigh(t *testing.T) {
	// "999.0.0" is above any real kernel version, so the check must fail.
	c := &OSVersionCheck{}
	params := map[string]interface{}{
		"min_version": "999.0.0",
	}
	result := c.Run(context.Background(), params)
	require.NotNil(t, result)
	assert.Equal(t, StatusFail, result.Status)
	assert.Equal(t, float64(0), result.Score)
	assert.NotEmpty(t, result.Remediation)
}

func TestOSVersionCheck_Run_NoMinVersion(t *testing.T) {
	c := &OSVersionCheck{}
	params := map[string]interface{}{}
	result := c.Run(context.Background(), params)
	require.NotNil(t, result)
	assert.Equal(t, StatusPass, result.Status)
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"5.15.0", "5.4.0", 1},
		{"5.4.0", "5.15.0", -1},
		{"6.0", "5.15.0", 1},
		{"0.0.1", "0.0.1", 0},
		{"", "", 0},
	}

	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		assert.Equal(t, tt.want, got, "compareVersions(%q, %q)", tt.a, tt.b)
	}
}
