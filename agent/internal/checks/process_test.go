package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessCheck_Name(t *testing.T) {
	c := &ProcessCheck{}
	assert.Equal(t, "process_running", c.Name())
}

func TestProcessCheck_Run_NilParams(t *testing.T) {
	c := &ProcessCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	// No processes configured → pass.
	assert.Equal(t, StatusPass, result.Status)
	assert.Equal(t, 1.0, result.Score)
}

func TestProcessCheck_Run_EmptyProcessList(t *testing.T) {
	c := &ProcessCheck{}
	params := map[string]interface{}{
		"processes": []interface{}{},
	}
	result := c.Run(context.Background(), params)
	require.NotNil(t, result)
	assert.Equal(t, StatusPass, result.Status)
}

func TestProcessCheck_Run_NonexistentProcess(t *testing.T) {
	c := &ProcessCheck{}
	params := map[string]interface{}{
		"processes": []interface{}{"this-process-definitely-does-not-exist-xyz123"},
	}
	result := c.Run(context.Background(), params)
	require.NotNil(t, result)
	assert.Equal(t, StatusFail, result.Status)
	assert.Equal(t, float64(0), result.Score)
	assert.NotEmpty(t, result.Message)
	assert.NotEmpty(t, result.Remediation)
}

func TestProcessCheck_Run_MixedProcesses(t *testing.T) {
	// One process that almost certainly runs (init/systemd or PID 1) and one
	// that definitely does not.
	c := &ProcessCheck{}
	params := map[string]interface{}{
		"processes": []interface{}{
			"this-process-definitely-does-not-exist-xyz123",
			"another-nonexistent-process-abc987",
		},
	}
	result := c.Run(context.Background(), params)
	require.NotNil(t, result)
	assert.Equal(t, StatusFail, result.Status)
	assert.GreaterOrEqual(t, result.Score, float64(0))
	assert.LessOrEqual(t, result.Score, float64(1))
}

func TestParseProcessList(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]interface{}
		want   []string
	}{
		{
			name:   "nil params",
			params: nil,
			want:   nil,
		},
		{
			name:   "missing key",
			params: map[string]interface{}{},
			want:   nil,
		},
		{
			name: "valid list",
			params: map[string]interface{}{
				"processes": []interface{}{"foo", "bar"},
			},
			want: []string{"foo", "bar"},
		},
		{
			name: "filters empty strings",
			params: map[string]interface{}{
				"processes": []interface{}{"foo", "", "bar"},
			},
			want: []string{"foo", "bar"},
		},
		{
			name: "wrong type",
			params: map[string]interface{}{
				"processes": "not-a-slice",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		got := parseProcessList(tt.params)
		assert.Equal(t, tt.want, got, tt.name)
	}
}
