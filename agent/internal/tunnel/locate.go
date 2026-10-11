package tunnel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ErrNotInstalled is returned when no tunneler binary can be found.
var ErrNotInstalled = errors.New("ziti-edge-tunnel is not installed")

// ErrUntrustedBinary is returned for a tunneler binary that a non-privileged
// account could have replaced.
var ErrUntrustedBinary = errors.New("the tunneler binary is not safe to run")

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
//
// PATH is deliberately NOT searched. The agent runs as LocalSystem or root,
// and a PATH lookup made with those privileges executes whatever the first
// writable PATH entry holds: on Windows that list often contains per-user and
// tool directories an ordinary account can write.
func candidates(agentExe string) []string {
	dir := filepath.Dir(agentExe)
	name := BinaryName()
	return []string{
		filepath.Join(dir, name),
		filepath.Join(dir, "..", "lib", "openidx-agent", name),
	}
}

// verifyBinary decides whether a tunneler binary may be run. A variable only
// so this package's tests, whose binaries live under the world-writable
// temporary directory, can substitute a check that accepts them; nothing
// outside the package can reach it.
var verifyBinary = func(path string) error { return verifyTrustedBinary(path, "") }

// Locate finds the tunneler binary. An explicit path (tunnel.binary_path,
// which the agent passes only from a trusted agent.json) is used as given;
// otherwise the bundled locations next to agentExe are tried. agentExe ""
// means os.Executable(). Whichever is found must pass verifyBinary: a binary
// an ordinary account could have replaced is never run, and it does not fall
// through to another candidate, because that would hide the tampering.
func Locate(explicit, agentExe string) (string, error) {
	if explicit != "" {
		if !filepath.IsAbs(explicit) {
			return "", fmt.Errorf("%w: tunnel.binary_path %q is not an absolute path", ErrNotInstalled, explicit)
		}
		if err := isExecutableFile(explicit); err != nil {
			return "", fmt.Errorf("%w: tunnel.binary_path %s: %v", ErrNotInstalled, explicit, err)
		}
		if err := verifyBinary(explicit); err != nil {
			return "", err
		}
		return filepath.Clean(explicit), nil
	}
	if agentExe == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("%w: cannot find the agent's own directory: %v", ErrNotInstalled, err)
		}
		agentExe = exe
	}
	if resolved, err := filepath.EvalSymlinks(agentExe); err == nil {
		agentExe = resolved
	}
	for _, c := range candidates(agentExe) {
		c = filepath.Clean(c)
		if isExecutableFile(c) != nil {
			continue
		}
		if err := verifyBinary(c); err != nil {
			return "", err
		}
		return c, nil
	}
	return "", ErrNotInstalled
}

func isExecutableFile(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("is not a regular file")
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		return errors.New("is not executable")
	}
	return nil
}
