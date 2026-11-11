package oidcrp

import (
	"context"
	"errors"
	"testing"

	"github.com/openidx/openidx/internal/common/netutil"
)

func TestLoopbackIssuerRefusedWithoutFlag(t *testing.T) {
	t.Setenv(AllowLoopbackEnv, "")
	if err := checkIssuerURL("http://127.0.0.1:8080"); !errors.Is(err, ErrInsecureIssuer) {
		t.Fatalf("http loopback without flag: got %v", err)
	}
}

func TestGuardedClientRefusesInternalAddresses(t *testing.T) {
	t.Setenv(AllowLoopbackEnv, "")
	d := NewDiscoverer(nil)
	for _, iss := range []string{"https://169.254.169.254", "https://10.0.0.1", "https://127.0.0.1"} {
		_, err := d.Discover(context.Background(), iss, "")
		if err == nil || !errors.Is(err, netutil.ErrDestinationNotAllowed) {
			t.Errorf("%s: want destination refusal, got %v", iss, err)
		}
	}
}

func TestGuardedClientReachesLoopbackWithFlag(t *testing.T) {
	p := newFakeProvider(t)
	d := NewDiscoverer(nil)
	if _, err := d.Discover(context.Background(), p.srv.URL, ""); err != nil {
		t.Fatalf("loopback provider with flag: %v", err)
	}
}
