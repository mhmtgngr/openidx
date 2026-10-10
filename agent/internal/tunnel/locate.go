package tunnel

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ErrNotInstalled is returned when no tunneler binary can be found.
var ErrNotInstalled = errors.New("ziti-edge-tunnel is not installed")

// BinaryName is the tunneler's file name on this platform.
func BinaryName() string {
	if runtime.GOOS == "windows" {
		return "ziti-edge-tunnel.exe"
	}
	return "ziti-edge-tunnel"
}

// candidates is where a bundled tunneler sits relative to the agent binary, in
// the order they are tried:
//
//   - next to the agent: the MSI installs both into %ProgramFiles%\OpenIDX;
//   - <agent dir>/../lib/openidx-agent: the deb/rpm put the agent in
//     /usr/local/bin and the tunneler in /usr/local/lib/openidx-agent, so it
//     does not land on everyone's PATH beside an operator's own OpenZiti
//     install.
func candidates(agentExe string) []string {
	dir := filepath.Dir(agentExe)
	name := BinaryName()
	return []string{
		filepath.Join(dir, name),
		filepath.Join(dir, "..", "lib", "openidx-agent", name),
	}
}

// Locate finds the tunneler binary. An explicit path (tunnel.binary_path) is
// used as given and must exist; otherwise the bundled locations next to
// agentExe are tried, then PATH. agentExe "" means os.Executable().
func Locate(explicit, agentExe string) (string, error) {
	if explicit != "" {
		if err := isExecutableFile(explicit); err != nil {
			return "", fmt.Errorf("%w: tunnel.binary_path %s: %v", ErrNotInstalled, explicit, err)
		}
		return explicit, nil
	}
	if agentExe == "" {
		if exe, err := os.Executable(); err == nil {
			agentExe = exe
		}
	}
	if agentExe != "" {
		for _, c := range candidates(agentExe) {
			if isExecutableFile(c) == nil {
				return filepath.Clean(c), nil
			}
		}
	}
	if p, err := exec.LookPath(BinaryName()); err == nil {
		return p, nil
	}
	return "", ErrNotInstalled
}

func isExecutableFile(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return errors.New("is a directory")
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		return errors.New("is not executable")
	}
	return nil
}
