//go:build windows

package updater

import "os/exec"

// apply launches an unattended MSI upgrade. MajorUpgrade in the MSI stops the
// service, swaps the files, and restarts it; msiexec runs as a detached process
// so it survives the service being stopped mid-update.
func apply(msiPath string) error {
	return exec.Command("msiexec", "/i", msiPath, "/qn", "/norestart").Start()
}

// applyDowngrade installs an older MSI over a newer one. The package's
// MajorUpgrade allows downgrades; REINSTALLMODE=vomus makes Windows Installer
// replace every file whatever its version, so the older binaries really land.
func applyDowngrade(msiPath string) error {
	return exec.Command("msiexec", "/i", msiPath, "REINSTALLMODE=vomus", "/qn", "/norestart").Start()
}
