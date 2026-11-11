package oidcrp

import (
	"os"
	"testing"
)

// The test providers are httptest servers on 127.0.0.1.
func TestMain(m *testing.M) {
	os.Setenv(AllowLoopbackEnv, "1")
	os.Exit(m.Run())
}
