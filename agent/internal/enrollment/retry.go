package enrollment

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/transport"
)

// RetrySchedule is the wait before each enrolment retry: 1m, 5m, 15m, then
// hourly for as long as the device stays unenrolled. Fast enough that a
// device installed before its network came up enrols within minutes of it,
// slow enough that a fleet of thousands with a bad token does not hammer the
// server.
var RetrySchedule = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// RetryDelay is the wait before retry n (0-based).
func RetryDelay(n int) time.Duration {
	if n < 0 {
		n = 0
	}
	if n >= len(RetrySchedule) {
		return RetrySchedule[len(RetrySchedule)-1]
	}
	return RetrySchedule[n]
}

// Clock is the time source RetryEnroll waits on; tests inject a fake.
type Clock interface {
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RealClock is the wall clock.
var RealClock Clock = realClock{}

// EnrollFunc performs one enrolment attempt.
type EnrollFunc func(logger *zap.Logger, o Options) (*EnrollResult, error)

// RetryEnroll finishes an enrolment the installer could not: while configDir
// holds no enrolment and a sealed token exists, it tries to enrol with it,
// waiting RetryDelay between attempts. It returns nil once the device is
// enrolled (by this loop or by anything else writing agent.json), and stops
// without error when there is no sealed token or the server answered
// agent_revoked (the token is then deleted). It returns ctx.Err() on cancel.
func RetryEnroll(ctx context.Context, logger *zap.Logger, configDir string, clock Clock, enroll EnrollFunc) error {
	if clock == nil {
		clock = RealClock
	}
	if enroll == nil {
		enroll = EnrollWithOptions
	}
	for attempt := 0; ; attempt++ {
		if enrolled(configDir) {
			return nil
		}
		sealed, err := LoadSealedToken(configDir)
		if err != nil {
			logger.Warn("sealed enrolment token unreadable; not retrying", zap.Error(err))
			return nil
		}
		if sealed == nil {
			return nil
		}
		// The first attempt also waits: the service starts before the MSI's
		// enrol action runs, and must not race it.
		d := RetryDelay(attempt)
		logger.Info("device not enrolled; retrying with the sealed token",
			zap.Int("attempt", attempt+1), zap.Duration("in", d))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-clock.After(d):
		}
		if enrolled(configDir) {
			return nil
		}
		_, err = enroll(logger, OptionsFromSealed(configDir, *sealed))
		if err == nil {
			logger.Info("enrolment completed from the sealed token")
			return nil
		}
		if errors.Is(err, transport.ErrAgentRevoked) {
			// EnrollWithOptions deletes it; make sure for an injected enroll.
			_ = DeleteSealedToken(configDir)
			logger.Warn("the server revoked this device; the sealed token was deleted")
			return nil
		}
		logger.Warn("enrolment retry failed", zap.Error(err))
	}
}

func enrolled(configDir string) bool {
	cfg, err := agent.LoadConfig(configDir)
	return err == nil && cfg != nil && cfg.AgentID != ""
}
