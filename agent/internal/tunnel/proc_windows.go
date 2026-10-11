//go:build windows

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// createNoWindow keeps the console tunneler from opening a window when the
// agent is run by hand; under the service there is no desktop to open one on.
const createNoWindow = 0x08000000

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

func configureChild(cmd *exec.Cmd) { hideWindow(cmd) }

// defaultPrivileged is true: the agent service runs as LocalSystem, which is
// what the tunneler needs to create its Wintun adapter.
func defaultPrivileged() bool { return true }

// processGuard is a job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. Its
// handle lives as long as the agent process, so when the agent exits for any
// reason, crash included, Windows closes it and kills the tunneler with it.
// Without it a crashed agent would leave the tunneler running, holding the
// openidx IPC pipe and the adapter, and the restarted agent's tunneler would
// fail against it.
type processGuard struct {
	job windows.Handle
}

func newProcessGuard() (*processGuard, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return &processGuard{job: job}, nil
}

func (g *processGuard) adopt(p *os.Process) error {
	if g == nil || g.job == 0 {
		return nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(g.job, h); err != nil {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

func (g *processGuard) close() {
	if g != nil && g.job != 0 {
		_ = windows.CloseHandle(g.job)
		g.job = 0
	}
}

// terminate kills the tunneler. A console process started without a console
// of its own cannot be sent Ctrl+C from here, so there is no gentler request
// to make.
func terminate(p *os.Process, done <-chan struct{}, _ time.Duration) {
	_ = p.Kill()
	<-done
}
