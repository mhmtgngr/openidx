package access

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// TestSeverUserZitiCircuitsNoZitiNoop verifies the mid-session termination
// helper is a safe no-op when the overlay is not active (nil ZitiManager) and
// when the user has no id — it must never panic or error the revoke path (Wave
// A3: continuous-verify severs live Ziti circuits on a posture/risk degrade,
// but only when the overlay is active).
func TestSeverUserZitiCircuitsNoZitiNoop(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	// No ZitiManager set -> ziti() returns nil -> immediate, panic-free return.
	s.severUserZitiCircuits(context.Background(), "user-1", "posture_fail")
	s.severUserZitiCircuits(context.Background(), "", "posture_fail")
}
