package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkExe(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestLocateUsesOnlyTheInstallDirsNeverPATH(t *testing.T) {
	dir := t.TempDir()
	agentExe := filepath.Join(dir, "bin", "openidx-agent")

	// A tunneler on PATH is never run by the privileged agent.
	onPath := filepath.Join(dir, "path", BinaryName())
	mkExe(t, onPath)
	t.Setenv("PATH", filepath.Dir(onPath))
	if got, err := Locate("", agentExe); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("PATH only: got %q, %v; want ErrNotInstalled", got, err)
	}

	libDir := filepath.Join(dir, "lib", "openidx-agent", BinaryName())
	mkExe(t, libDir)
	if got, _ := Locate("", agentExe); got != libDir {
		t.Fatalf("lib dir: got %q, want %q", got, libDir)
	}
	beside := filepath.Join(dir, "bin", BinaryName())
	mkExe(t, beside)
	if got, _ := Locate("", agentExe); got != beside {
		t.Fatalf("beside the agent: got %q, want %q", got, beside)
	}

	if _, err := Locate(filepath.Join(dir, "missing"), agentExe); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("a missing explicit path must not fall back: err = %v", err)
	}
	if _, err := Locate("relative/"+BinaryName(), agentExe); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("a relative binary_path was accepted: err = %v", err)
	}
}

func TestLocateRefusesABinaryTheTrustCheckRejects(t *testing.T) {
	dir := t.TempDir()
	agentExe := filepath.Join(dir, "bin", "openidx-agent")
	beside := filepath.Join(dir, "bin", BinaryName())
	lib := filepath.Join(dir, "lib", "openidx-agent", BinaryName())
	mkExe(t, beside)
	mkExe(t, lib)

	prev := verifyBinary
	t.Cleanup(func() { verifyBinary = prev })
	verifyBinary = func(p string) error {
		if p == beside {
			return ErrUntrustedBinary
		}
		return nil
	}
	// It does not fall through to the next candidate: a planted binary is a
	// fault to report, not something to route around silently.
	if got, err := Locate("", agentExe); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("got %q, %v; want ErrUntrustedBinary", got, err)
	}
	if _, err := Locate(beside, agentExe); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("an untrusted explicit binary_path was accepted: %v", err)
	}
}

func TestAgentIDMustBeASafeFileName(t *testing.T) {
	for _, ok := range []string{"agent-1", "6f4a1e2c-2b7d-4b1a-9c3e-0a1b2c3d4e5f", "A_b-9"} {
		if _, err := IdentityFileName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../x", "..", "a/b", `a\b`, "C:evil", "x.json", " a", "-a",
		"a\x00b", strings.Repeat("a", 65), "a b"} {
		if _, err := IdentityFileName(bad); !errors.Is(err, ErrBadAgentID) {
			t.Errorf("%q accepted (err=%v)", bad, err)
		}
	}
}

func TestProvisionRefusesATraversingAgentIDAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "ziti-identity.json")
	writeFile(t, src, `{"ztAPI":"https://c","id":{}}`)
	idDir := filepath.Join(dir, "tunnel", "identities")
	p := &Provisioner{Source: src, Dir: idDir, AgentID: "../../escaped"}
	if _, err := p.Provision(); !errors.Is(err, ErrBadAgentID) {
		t.Fatalf("err = %v, want ErrBadAgentID", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escaped.json")); !os.IsNotExist(err) {
		t.Fatal("an identity was written outside the identity directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "dev-..", "..", "escaped.json")); err == nil {
		t.Fatal("an identity was written outside the identity directory")
	}
}

func TestStaleRemovalTouchesOnlyTheIdentityDirectory(t *testing.T) {
	dir := t.TempDir()
	idDir := filepath.Join(dir, "ids")
	outside := filepath.Join(dir, "dev-outside.json")
	writeFile(t, outside, `{}`)
	writeFile(t, filepath.Join(idDir, "dev-stale.json"), `{}`)
	if err := os.Symlink(outside, filepath.Join(idDir, "dev-link.json")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := (&Provisioner{Dir: idDir}).Forget(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("a file outside the identity directory was removed through a symlink")
	}
	if _, err := os.Lstat(filepath.Join(idDir, "dev-stale.json")); !os.IsNotExist(err) {
		t.Error("the stale identity was kept")
	}

	// An identity directory that is itself a symlink is refused outright.
	linkDir := filepath.Join(dir, "linked-ids")
	if err := os.Symlink(dir, linkDir); err != nil {
		t.Skip("directory symlinks unavailable:", err)
	}
	if _, err := (&Provisioner{Dir: linkDir}).Forget(); err == nil {
		t.Error("a symlinked identity directory was walked")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("removal followed a symlinked identity directory")
	}
	src := filepath.Join(dir, "src.json")
	writeFile(t, src, `{}`)
	if _, err := (&Provisioner{Source: src, Dir: linkDir, AgentID: "a1"}).Provision(); err == nil {
		t.Error("the private key was written through a symlinked identity directory")
	}
}
