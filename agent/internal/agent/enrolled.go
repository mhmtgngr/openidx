package agent

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
)

// ErrNotEnrolled says the config directory holds no enrolment: there is no
// agent.json, or it names no agent. It is a state, not a fault: the device
// has not been enrolled yet, and will be, from a link, a code or an installer
// property.
var ErrNotEnrolled = errors.New("this device is not enrolled")

// IsNotEnrolled reports whether err is the not-enrolled state.
func IsNotEnrolled(err error) bool { return errors.Is(err, ErrNotEnrolled) }

// WaitEnrolled returns an agent as soon as the device is enrolled, checking
// the config directory every interval until then or until ctx ends. Any
// failure other than not-enrolled is returned at once.
//
// The Windows service used to create its agent once at start and stop itself
// when that failed, with no recovery action registered, so a device enrolled
// after the service started ran no posture loop until the next reboot. The
// MSI starts the service before the enrolment custom action runs, so that was
// every install.
func WaitEnrolled(ctx context.Context, logger *zap.Logger, configDir string, interval time.Duration) (*Agent, error) {
	announced := false
	for {
		a, err := NewAgent(logger, configDir)
		if err == nil {
			if announced {
				logger.Info("device enrolled; starting the posture loop", zap.String("agent_id", a.config.AgentID))
			}
			return a, nil
		}
		if !IsNotEnrolled(err) {
			return nil, err
		}
		if !announced {
			logger.Info("device not enrolled yet; waiting for an enrolment",
				zap.String("config_dir", configDir), zap.Duration("recheck", interval))
			announced = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}
