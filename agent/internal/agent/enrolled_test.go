package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAMissingOrEmptyConfigIsNotEnrolled(t *testing.T) {
	_, err := NewAgent(zap.NewNop(), t.TempDir())
	require.True(t, IsNotEnrolled(err), "no agent.json: %v", err)

	dir := t.TempDir()
	saveTestConfig(t, dir, &AgentConfig{ServerURL: "https://openidx.test"})
	_, err = NewAgent(zap.NewNop(), dir)
	require.True(t, IsNotEnrolled(err), "agent.json without an agent id: %v", err)

	enrolled := t.TempDir()
	saveTestConfig(t, enrolled, &AgentConfig{ServerURL: "https://openidx.test", AgentID: "a1", AuthToken: "tok"})
	_, err = NewAgent(zap.NewNop(), enrolled)
	require.NoError(t, err)
}

func TestWaitEnrolledReturnsOnceTheDeviceIsEnrolled(t *testing.T) {
	dir := t.TempDir()
	go func() {
		time.Sleep(60 * time.Millisecond)
		_ = (&AgentConfig{ServerURL: "https://openidx.test", AgentID: "a1", AuthToken: "tok"}).Save(dir)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := WaitEnrolled(ctx, zap.NewNop(), dir, 10*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, "a1", a.config.AgentID)
}

func TestWaitEnrolledStopsWhenTheServiceStops(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := WaitEnrolled(ctx, zap.NewNop(), t.TempDir(), 10*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestWaitEnrolledDoesNotHideARealFault(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeRawConfig(dir, []byte("{not json")))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := WaitEnrolled(ctx, zap.NewNop(), dir, 10*time.Millisecond)
	require.Error(t, err)
	require.False(t, IsNotEnrolled(err), "a corrupt file is a fault to report, not an enrolment to wait for: %v", err)
}
