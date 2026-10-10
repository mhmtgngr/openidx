//go:build windows

package tunnel

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestJobObjectKillsTheTunnelerWithTheAgent: closing the guard's job handle,
// which Windows does when the agent process dies, must take the tunneler with
// it, so a crashed agent leaves no orphan holding the IPC pipe and adapter.
func TestJobObjectKillsTheTunnelerWithTheAgent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(fakeEnv, "1")
	t.Setenv(fakeRunEnv, "stay")
	t.Setenv(fakeStartsEnv, filepath.Join(dir, "starts.txt"))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	g, err := newProcessGuard()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "run", "--identity-dir", dir, "-P", IPCDiscriminator)
	configureChild(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	if err := g.adopt(cmd.Process); err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	g.close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the tunneler outlived its job object")
	}
}
