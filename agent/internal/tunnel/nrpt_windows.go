//go:build windows

package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// ErrNamesUnsupported is returned where there is no name-resolution hook; on
// Windows it is the PowerShell that cannot be found.
var ErrNamesUnsupported = fmt.Errorf("name resolution by the agent needs Windows PowerShell")

type winRules struct{}

func newNameRules() nameRules { return winRules{} }

// powershellPath is Windows PowerShell under the system directory the OS
// reports, never one found through PATH: the agent runs as LocalSystem.
func powershellPath() (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe"), nil
}

func (winRules) Supported() error {
	p, err := powershellPath()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNamesUnsupported, err)
	}
	if _, err := exec.LookPath(p); err != nil {
		return fmt.Errorf("%w: %v", ErrNamesUnsupported, err)
	}
	return nil
}

func (w winRules) Apply(names []string, server string) error {
	s, err := nrptApplyScript(names, server)
	if err != nil {
		return err
	}
	return runPowerShell(s)
}

func (w winRules) Clear(restore []string) error {
	s, err := nrptClearScript(restore, tunnelerDNS)
	if err != nil {
		return err
	}
	return runPowerShell(s)
}

// runPowerShell runs script as an encoded command (no quoting to get wrong, and
// nothing is written to disk) and fails with its output when it exits non-zero.
func runPowerShell(script string) error {
	ps, err := powershellPath()
	if err != nil {
		return err
	}
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("name resolution rules: %w: %s", err, trimOutput(out))
	}
	return nil
}

func trimOutput(out []byte) string {
	const max = 400
	if len(out) > max {
		out = out[:max]
	}
	return string(out)
}
