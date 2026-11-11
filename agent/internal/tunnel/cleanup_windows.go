//go:build windows

package tunnel

import (
	"fmt"
	"os/exec"
	"syscall"
)

// cleanupScript removes what a killed ziti-edge-tunnel can leave behind: the
// NRPT rules it adds for overlay names (their comment names the tunneler) and
// a Wintun adapter left in the system. Each step tolerates absence.
const cleanupScript = `$ErrorActionPreference='SilentlyContinue'
Get-DnsClientNrptRule | Where-Object { $_.Comment -like '*ziti*' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like 'Wintun*' -or $_.Name -like 'ziti-tun*' } | ForEach-Object { Disable-NetAdapter -Name $_.Name -Confirm:$false }
Clear-DnsClientCache
exit 0`

// Cleanup removes the tunneler's NRPT rules and adapter after it was stopped.
// The MSI runs it (openidx-agent tunnel-cleanup) on uninstall, after the
// service is stopped, because on Windows the tunneler can only be killed.
func Cleanup() error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cleanupScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tunnel cleanup: %w: %s", err, out)
	}
	return nil
}
