//go:build !windows

package control

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The control socket has no bearer token on Unix: its filesystem permissions
// ARE the authentication, and what they guard is a surface with no second lock
// — /token hands out the signed-in user's access token, /pam/connect launches a
// privileged session, /ziti/dial opens the overlay.
//
// So "the socket is owner-only" is not a detail, it is the whole control, and
// it used to be established one step too late: net.Listen creates a unix socket
// at 0777 &^ umask, and a daemon's usual umask of 022 leaves it 0755 until the
// chmod on the next line. The path is a fixed name under $XDG_RUNTIME_DIR or
// /tmp, so it is not a window an attacker has to find.

// TestTheBindItselfIsOwnerOnly is the one that observes the WINDOW rather than
// the state after it closed. It calls the bind alone, under the umask a systemd
// service inherits, and reads the mode with no chmod in between — so it fails if
// the umask narrowing is ever dropped, which reading the mode after newListener
// would not, because the chmod would have repaired it by then.
func TestTheBindItselfIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.sock")

	prev := umaskForTest(t, 0o022)
	defer umaskForTest(t, prev)

	ln, err := bindOwnerOnly(path)
	if err != nil {
		t.Fatalf("bindOwnerOnly: %v", err)
	}
	defer ln.Close()

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Fatalf("the socket is mode %04o the instant it exists, before any chmod. Under a 022 "+
			"umask net.Listen creates it 0755, and at a predictable path that is a window in which "+
			"any local account can connect to a control surface with no other authentication. A "+
			"connection accepted in that window is not closed by a later chmod.", mode)
	}

	// And the umask must be restored, or every file the agent writes after
	// startup inherits 0600-only — including ones that are meant to be readable.
	if got := umaskForTest(t, 0o022); got != 0o022 {
		t.Errorf("bindOwnerOnly left the process umask at %04o instead of restoring 0022", got)
	}
}

func TestControlSocketIsOwnerOnlyFromTheMomentItExists(t *testing.T) {
	// XDG_RUNTIME_DIR is what socketPath() prefers, so pointing it at a temp
	// directory puts the real listener under this test's control without
	// touching the developer's own socket.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	// A umask that would leave the socket group- and world-readable if the
	// bind did not narrow it — the value a systemd service typically inherits.
	prev := umaskForTest(t, 0o022)
	defer umaskForTest(t, prev)

	ln, addr, token, err := newListener()
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	defer func() {
		_ = ln.Close()
		cleanupListener(addr)
	}()

	if token != "" {
		t.Errorf("the UDS listener returned a bearer token %q; on Unix the file mode is the control "+
			"and a token here would mean the server is enforcing something the test does not check", token)
	}

	fi, err := os.Lstat(addr)
	if err != nil {
		t.Fatalf("stat %s: %v", addr, err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("control socket is mode %04o, want 0600: anyone who can reach %s can drive the "+
			"engine, and there is no other authentication on this transport", mode, addr)
	}
}

// TestNewListenerRefusesANonSocketAtThePath keeps the pre-existing refusal: the
// path is in a world-writable directory when XDG_RUNTIME_DIR is unset, so
// something else being there is a reason to stop rather than to remove it.
func TestNewListenerRefusesANonSocketAtThePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "openidx-agent.sock"), []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, _, err := newListener(); err == nil {
		t.Error("newListener replaced a regular file at the control path")
	}
}

// TestTheDesktopClientLooksWhereTheAgentListens.
//
// socketPath() is duplicated: Go decides where the socket goes, and
// client/lib/engine/desktop_engine_client.dart decides where the GUI looks, in
// another language with nothing checking they agree. Same shape as the gomobile
// bindings, which are censused for the same reason — except that a mismatch
// here is not a compile error anywhere, it is a desktop client that reports the
// agent as not running.
func TestTheDesktopClientLooksWhereTheAgentListens(t *testing.T) {
	const dartFile = "../../../client/lib/engine/desktop_engine_client.dart"
	b, err := os.ReadFile(dartFile)
	if err != nil {
		t.Fatalf("%s: %v (this test reads the client's own source; if it moved, point here at the new path)", dartFile, err)
	}
	dart := string(b)

	m := regexp.MustCompile(`socketName\s*=\s*'([^']+)'`).FindStringSubmatch(dart)
	if m == nil {
		t.Fatal("desktop_engine_client.dart no longer declares socketName; the census cannot read it")
	}
	if want := filepath.Base(socketPath()); m[1] != want {
		t.Errorf("the Dart client looks for %q and the agent listens on %q: the desktop GUI would "+
			"report the agent as not running", m[1], want)
	}

	// And the directory rule, which is the half that actually differs between
	// machines: XDG_RUNTIME_DIR when set, the temp dir otherwise.
	if !strings.Contains(dart, "XDG_RUNTIME_DIR") {
		t.Error("the Dart client does not consult XDG_RUNTIME_DIR, which is where socketPath() puts " +
			"the socket on any machine that sets it")
	}
}
