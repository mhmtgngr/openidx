package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func setPin(t *testing.T, v string) {
	prev := PinnedBinarySHA256
	PinnedBinarySHA256 = v
	t.Cleanup(func() { PinnedBinarySHA256 = prev })
}

func TestHeldBinaryRunsAndHashes(t *testing.T) {
	t.Setenv(fakeEnv, "1")
	bin := installFake(t, t.TempDir())
	h, err := openBinary(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if h.sum != fileSHA(t, bin) {
		t.Fatalf("held sha %s, file sha %s", h.sum, fileSHA(t, bin))
	}
	if v := queryVersion(context.Background(), h, defaultTimeout); v != fakeVersion {
		t.Fatalf("version through the held binary = %q", v)
	}
	if err := h.verifyPin(); err != nil {
		t.Fatalf("unchanged binary failed verifyPin: %v", err)
	}
}

func TestThePinIsEnforcedAtOpenAndBeforeEveryStart(t *testing.T) {
	t.Setenv(fakeEnv, "1")
	bin := installFake(t, t.TempDir())

	setPin(t, strings.Repeat("0", 64))
	if _, err := openBinary(bin); !errors.Is(err, ErrBinaryMismatch) {
		t.Fatalf("a binary that does not match the pin was opened: %v", err)
	}

	setPin(t, fileSHA(t, bin))
	h, err := openBinary(bin)
	if err != nil {
		t.Fatalf("the pinned binary was refused: %v", err)
	}
	defer h.close()

	// The same file, changed in place after it was checked, is refused at
	// the next start.
	f, err := os.OpenFile(bin, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Skip("cannot modify the held file on this platform:", err)
	}
	_, _ = f.Write([]byte("tampered"))
	f.Close()
	if err := h.verifyPin(); !errors.Is(err, ErrBinaryMismatch) {
		t.Fatalf("a binary changed after its check passed verifyPin: %v", err)
	}
}

func TestASupervisorWithAMismatchedPinStartsNothing(t *testing.T) {
	e := newEnv(t, "stay")
	setPin(t, strings.Repeat("a", 64))
	s := New(e.config())
	s.SetEnabled(true)
	stop := runSupervisor(t, s)
	eventually(t, "degraded with a pin error", func() bool {
		return s.Status().State == StateDegraded && strings.Contains(s.Detail(), "pinned")
	})
	stop()
	if n := len(e.starts(t)); n != 0 {
		t.Fatalf("a binary that does not match the pin was started %d times", n)
	}
}
