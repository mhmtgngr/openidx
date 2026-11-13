package tunnel

import (
	"strings"
	"testing"
)

func pathOf(t *testing.T, env []string) string {
	t.Helper()
	var paths []string
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, "PATH") {
			paths = append(paths, v)
		}
	}
	if len(paths) != 1 {
		t.Fatalf("want exactly one PATH, got %d in %v", len(paths), env)
	}
	return paths[0]
}

// The pilot PC's machine PATH had no System32: the tunneler could not run
// powershell or netsh, so it never set its DNS or NRPT rules.
func TestTunnelerEnvPutsSystemDirectoriesFirst(t *testing.T) {
	env := tunnelerEnv([]string{`Path=D:\OpenSSH;C:\Program Files\nodejs`, "TEMP=C:\\Temp"}, `C:\Windows`)
	p := pathOf(t, env)
	if !strings.HasPrefix(strings.ToLower(p), strings.ToLower(`C:\Windows\System32;`)) {
		t.Fatalf("System32 must come first: %q", p)
	}
	for _, want := range []string{`WindowsPowerShell`, `Wbem`, `D:\OpenSSH`, `nodejs`} {
		if !strings.Contains(p, want) {
			t.Errorf("PATH lost %q: %q", want, p)
		}
	}
	if !contains(env, "TEMP=C:\\Temp") {
		t.Errorf("other variables must be kept: %v", env)
	}
}

func TestTunnelerEnvDoesNotDuplicate(t *testing.T) {
	p := pathOf(t, tunnelerEnv([]string{`PATH=C:\WINDOWS\system32\;C:\Windows;X`}, `C:\Windows`))
	n := 0
	for _, d := range strings.Split(p, ";") {
		if strings.EqualFold(strings.TrimRight(d, `\`), `C:\Windows\System32`) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("System32 appears %d times: %q", n, p)
	}
}

func TestTunnelerEnvWithoutAPath(t *testing.T) {
	p := pathOf(t, tunnelerEnv([]string{"A=1"}, ""))
	if !strings.Contains(p, `System32`) {
		t.Fatalf("a missing PATH still gets the system directories: %q", p)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
