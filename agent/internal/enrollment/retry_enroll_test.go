package enrollment

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/transport"
)

// fakeClock fires every wait at once and records what was asked for.
type fakeClock struct{ waits []time.Duration }

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.waits = append(c.waits, d)
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

func sealFor(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, SealToken(dir, SealedToken{ServerURL: "https://openidx.test", Token: "fleet"}))
}

func TestRetryDelayBacksOff1m5m15mThenHourly(t *testing.T) {
	want := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour, time.Hour}
	for i, w := range want {
		assert.Equal(t, w, RetryDelay(i), "retry %d", i)
	}
}

func TestRetryEnrollKeepsTryingWithBackoffUntilEnrolled(t *testing.T) {
	dir := t.TempDir()
	sealFor(t, dir)
	clock := &fakeClock{}
	calls := 0
	enroll := func(_ *zap.Logger, o Options) (*EnrollResult, error) {
		calls++
		assert.Equal(t, "fleet", o.Token)
		assert.True(t, o.KeepToken)
		if calls < 5 {
			return nil, fmt.Errorf("network down")
		}
		cfg := &agent.AgentConfig{ServerURL: o.ServerURL, AgentID: "a1", AuthToken: "x"}
		require.NoError(t, cfg.Save(dir))
		return &EnrollResult{AgentConfig: cfg}, nil
	}
	require.NoError(t, RetryEnroll(context.Background(), zap.NewNop(), dir, clock, enroll))
	assert.Equal(t, 5, calls)
	assert.Equal(t, []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour}, clock.waits)
}

func TestRetryEnrollDoesNothingWithoutASealedToken(t *testing.T) {
	clock := &fakeClock{}
	err := RetryEnroll(context.Background(), zap.NewNop(), t.TempDir(), clock, func(*zap.Logger, Options) (*EnrollResult, error) {
		t.Fatal("must not enrol without a sealed token")
		return nil, nil
	})
	require.NoError(t, err)
	assert.Empty(t, clock.waits)
}

func TestRetryEnrollDoesNothingWhenAlreadyEnrolled(t *testing.T) {
	dir := t.TempDir()
	sealFor(t, dir)
	require.NoError(t, (&agent.AgentConfig{AgentID: "a1"}).Save(dir))
	clock := &fakeClock{}
	require.NoError(t, RetryEnroll(context.Background(), zap.NewNop(), dir, clock, func(*zap.Logger, Options) (*EnrollResult, error) {
		t.Fatal("already enrolled")
		return nil, nil
	}))
	assert.Empty(t, clock.waits)
}

func TestRetryEnrollStopsAndDeletesTokenOnRevoke(t *testing.T) {
	dir := t.TempDir()
	sealFor(t, dir)
	calls := 0
	err := RetryEnroll(context.Background(), zap.NewNop(), dir, &fakeClock{}, func(*zap.Logger, Options) (*EnrollResult, error) {
		calls++
		return nil, fmt.Errorf("enroll request: %w", transport.ErrAgentRevoked)
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	got, lerr := LoadSealedToken(dir)
	require.NoError(t, lerr)
	assert.Nil(t, got)
}

func TestRetryEnrollHonoursCancel(t *testing.T) {
	dir := t.TempDir()
	sealFor(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RetryEnroll(ctx, zap.NewNop(), dir, blockingClock{}, nil)
	assert.True(t, errors.Is(err, context.Canceled))
}

type blockingClock struct{}

func (blockingClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }
