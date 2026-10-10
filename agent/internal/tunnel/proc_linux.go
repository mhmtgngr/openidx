//go:build linux

package tunnel

import (
	"os/exec"
	"syscall"
)

// configureChild asks the kernel to SIGTERM the tunneler if the agent dies, so
// an agent crash does not leave an orphan holding the TUN device and the IPC
// socket for the next agent to collide with.
func configureChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
