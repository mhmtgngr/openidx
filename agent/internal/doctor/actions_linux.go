//go:build linux

package doctor

import (
	"context"
	"os"
	"os/exec"
)

// linuxUnit is the systemd unit the packages install.
const linuxUnit = "openidx-agent"

type osActions struct{}

func (osActions) FlushDNS(ctx context.Context) error {
	bin, err := exec.LookPath("resolvectl")
	if err != nil {
		return ErrUnsupported
	}
	return exec.CommandContext(ctx, bin, "flush-caches").Run()
}

func (osActions) RestartService(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return ErrNeedsElevation
	}
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return ErrUnsupported
	}
	return exec.CommandContext(ctx, bin, "restart", linuxUnit).Run()
}
