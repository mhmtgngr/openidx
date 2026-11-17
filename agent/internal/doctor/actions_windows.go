//go:build windows

package doctor

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type osActions struct{}

// FlushDNS runs ipconfig from the system directory, never from PATH.
func (osActions) FlushDNS(ctx context.Context) error {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	return exec.CommandContext(ctx, filepath.Join(dir, "ipconfig.exe"), "/flushdns").Run()
}

func (osActions) RestartService(ctx context.Context) error {
	m, err := mgr.Connect()
	if err != nil {
		return elevation(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(WindowsServiceName)
	if err != nil {
		return elevation(err)
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return elevation(err)
	}
	if st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return elevation(err)
		}
		deadline := time.Now().Add(20 * time.Second)
		for st.State != svc.Stopped {
			if time.Now().After(deadline) {
				return errors.New("service did not stop in time")
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
			if st, err = s.Query(); err != nil {
				return elevation(err)
			}
		}
	}
	return elevation(s.Start())
}

func elevation(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return ErrNeedsElevation
	}
	return err
}
