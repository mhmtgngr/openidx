//go:build !windows

package tunnel

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// hideWindow is a no-op off Windows.
func hideWindow(*exec.Cmd) {}

// processGuard is a no-op off Windows: Linux children get a parent-death
// signal (proc_linux.go), and elsewhere there is nothing equivalent to set.
type processGuard struct{}

func newProcessGuard() (*processGuard, error) { return &processGuard{}, nil }
func (*processGuard) adopt(*os.Process) error { return nil }
func (*processGuard) close()                  {}

// defaultPrivileged reports whether this process may run the tunneler itself:
// it needs root (CAP_NET_ADMIN) to open a TUN device.
func defaultPrivileged() bool { return os.Geteuid() == 0 }

// terminate asks the tunneler to stop with SIGTERM, which it handles by
// removing its routes and DNS entries, and kills it if it has not exited
// within grace. done is closed when the process has been reaped.
func terminate(p *os.Process, done <-chan struct{}, grace time.Duration) {
	_ = p.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(grace):
		_ = p.Kill()
		<-done
	}
}
