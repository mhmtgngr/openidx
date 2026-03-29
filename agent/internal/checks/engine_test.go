package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_RunChecks(t *testing.T) {
	r := NewRegistry()

	r.Register("pass_check", &mockCheck{
		name: "pass_check",
		result: &CheckResult{
			Status:  StatusPass,
			Score:   1.0,
			Message: "everything is fine",
		},
	})
	r.Register("fail_check", &mockCheck{
		name: "fail_check",
		result: &CheckResult{
			Status:      StatusFail,
			Score:       0.0,
			Message:     "something is wrong",
			Remediation: "fix it",
		},
	})

	engine := NewEngine(r)

	configs := []CheckConfig{
		{Type: "pass_check", Severity: "low", Interval: "1h"},
		{Type: "fail_check", Severity: "high", Interval: "30m"},
	}

	results := engine.RunChecks(context.Background(), configs)

	require.Len(t, results, 2)

	assert.Equal(t, "pass_check", results[0].CheckType)
	assert.Equal(t, "low", results[0].Severity)
	assert.Equal(t, StatusPass, results[0].Result.Status)
	assert.Equal(t, 1.0, results[0].Result.Score)
	assert.False(t, results[0].RanAt.IsZero())

	assert.Equal(t, "fail_check", results[1].CheckType)
	assert.Equal(t, "high", results[1].Severity)
	assert.Equal(t, StatusFail, results[1].Result.Status)
	assert.Equal(t, 0.0, results[1].Result.Score)
	assert.Equal(t, "fix it", results[1].Result.Remediation)
	assert.False(t, results[1].RanAt.IsZero())
}

func TestEngine_SkipsUnknownCheck(t *testing.T) {
	r := NewRegistry()
	engine := NewEngine(r)

	configs := []CheckConfig{
		{Type: "does_not_exist", Severity: "critical", Interval: "5m"},
	}

	results := engine.RunChecks(context.Background(), configs)

	require.Len(t, results, 1)
	assert.Equal(t, "does_not_exist", results[0].CheckType)
	assert.Equal(t, "critical", results[0].Severity)
	assert.Equal(t, StatusError, results[0].Result.Status)
	assert.Contains(t, results[0].Result.Message, "does_not_exist")
	assert.False(t, results[0].RanAt.IsZero())
}
