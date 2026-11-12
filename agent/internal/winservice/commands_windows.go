//go:build windows

package winservice

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/openidx/openidx/agent/internal/agent"
)

// commandHooks are the service's half of the fleet commands (B8.6).
func (h *handler) commandHooks() agent.CommandHooks {
	return agent.CommandHooks{
		// Exit non-zero: the service's recovery actions (MSI util:ServiceConfig
		// and Install) restart it ten seconds later.
		Restart: func() {
			h.logger.Info("service: restarting on a fleet command")
			_ = h.logger.Sync()
			os.Exit(1)
		},
		UpdateNow: func() {
			select {
			case h.updateNow <- struct{}{}:
			default:
			}
		},
		Uninstall: uninstallProduct,
		LogFiles: func() []string {
			return []string{filepath.Join(h.configDir, "agent.log"), filepath.Join(h.configDir, "tray.log")}
		},
	}
}

// uninstallKey is where Windows Installer lists installed products.
const uninstallKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// productCode finds the installed OpenIDX Agent's product code.
func productCode() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "{") {
			continue
		}
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, _ := sk.GetStringValue("DisplayName")
		sk.Close()
		if name == "OpenIDX Agent" {
			return n, nil
		}
	}
	return "", errors.New("the OpenIDX Agent product is not registered with Windows Installer")
}

// uninstallProduct starts msiexec /x detached from this service, which the
// removal stops.
func uninstallProduct() error {
	code, err := productCode()
	if err != nil {
		return err
	}
	cmd := exec.Command("msiexec", "/x", code, "/qn", "/norestart") //nolint:gosec // product code read from HKLM, written by Windows Installer
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	return cmd.Start()
}
