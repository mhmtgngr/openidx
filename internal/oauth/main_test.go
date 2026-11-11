package oauth

import (
	"os"
	"testing"

	"github.com/openidx/openidx/internal/federation/oidcrp"
)

// TestMain lets the federated sign-in tests' httptest providers, which listen
// on loopback, be reached through the relying party's outbound guard.
func TestMain(m *testing.M) {
	_ = os.Setenv(oidcrp.AllowLoopbackEnv, "1")
	os.Exit(m.Run())
}
