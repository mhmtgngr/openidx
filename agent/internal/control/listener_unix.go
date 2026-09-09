//go:build !windows

package control

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// socketPath returns the control socket path: $XDG_RUNTIME_DIR/openidx-agent.sock
// when set, else /tmp/openidx-agent.sock.
func socketPath() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "openidx-agent.sock")
}

// newListener creates a 0600 Unix domain socket, removing any stale socket
// first. The empty token signals to the server that no bearer is required —
// filesystem permissions (owner-only) are the access control on UDS.
//
// THE WINDOW THIS CLOSES. The sequence used to be `net.Listen` then
// `os.Chmod(0600)`, and a unix socket is created with 0777 &^ umask. A daemon's
// usual umask is 022, so between those two calls the socket sat at 0755 —
// world-connectable — at a path anyone can predict, because socketPath() is a
// fixed name under $XDG_RUNTIME_DIR or, failing that, /tmp. Whoever connected in
// that window reached a control surface with no other authentication: /token
// hands out the signed-in user's access token, /pam/connect launches a
// privileged session, /ziti/dial opens the overlay. The chmod that followed
// would not have closed an already-accepted connection.
//
// Narrowing the umask around the bind makes the socket 0600 from the moment it
// exists, so there is no window rather than a small one. Umask is
// process-global and not goroutine-safe, which is why it is set and restored
// around this one call: newListener runs once, at startup, before the agent
// starts anything that writes files.
//
// The chmod is kept. It is now belt rather than the control — it also repairs a
// socket left by an older build, and it fails loudly if the umask had no effect
// on some filesystem that ignores permission bits for sockets.
func newListener() (ln net.Listener, addr, token string, err error) {
	path := socketPath()
	// Remove a stale socket left by a crashed prior run.
	if fi, statErr := os.Stat(path); statErr == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, "", "", fmt.Errorf("control path %s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}

	ln, err = bindOwnerOnly(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, "", "", fmt.Errorf("chmod %s: %w", path, err)
	}
	return ln, path, "", nil
}

// bindOwnerOnly binds a Unix socket that is 0600 FROM THE MOMENT IT EXISTS.
//
// Separate from newListener so the invariant is testable without racing it: a
// test can call this under a permissive umask and read the mode with no chmod
// in between, which is the only way to observe the window rather than the state
// after it closed. Reading the mode after newListener proves the chmod ran; it
// says nothing about what the socket was in between.
func bindOwnerOnly(path string) (net.Listener, error) {
	prev := syscall.Umask(0o177) // clear everything but owner rw
	defer syscall.Umask(prev)
	return net.Listen("unix", path)
}

// cleanupListener removes the UDS file after shutdown.
func cleanupListener(addr string) {
	if addr != "" {
		_ = os.Remove(addr)
	}
}
