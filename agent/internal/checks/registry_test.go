package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCheck is a minimal Check implementation used in tests.
type mockCheck struct {
	name   string
	result *CheckResult
}

func (m *mockCheck) Name() string { return m.name }

func (m *mockCheck) Run(_ context.Context, _ map[string]interface{}) *CheckResult {
	return m.result
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()

	mc := &mockCheck{
		name:   "test_check",
		result: &CheckResult{Status: StatusPass, Score: 1.0, Message: "all good"},
	}

	r.Register("test_check", mc)

	got, ok := r.Get("test_check")
	require.True(t, ok, "expected to find registered check")
	assert.Equal(t, mc, got)
}

func TestRegistry_GetUnknown(t *testing.T) {
	r := NewRegistry()

	got, ok := r.Get("nonexistent")
	assert.False(t, ok, "expected false for unknown check")
	assert.Nil(t, got)
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()

	r.Register("zebra", &mockCheck{name: "zebra"})
	r.Register("alpha", &mockCheck{name: "alpha"})
	r.Register("middle", &mockCheck{name: "middle"})

	names := r.List()

	assert.Equal(t, []string{"alpha", "middle", "zebra"}, names)
}
