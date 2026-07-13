//go:build windows

package updater

import "os/exec"

// apply launches an unattended MSI upgrade. MajorUpgrade in the MSI stops the
// service, swaps the files, and restarts it; msiexec runs as a detached process
// so it survives the service being stopped mid-update.
func apply(msiPath string) error {
	return exec.Command("msiexec", "/i", msiPath, "/qn", "/norestart").Start()
}
