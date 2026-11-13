package tunnel

import (
	"strings"
)

// tunnelerEnv is the environment the Windows tunneler runs with: the
// service's own, with Windows' system directories put first on PATH.
//
// ziti-edge-tunnel sets the adapter's DNS server, its interface metric and the
// NRPT rules that send intercepted names to its resolver by running
// `powershell -Command ...` and `netsh` found on PATH. A machine whose PATH
// had lost %SystemRoot%\System32 (seen on a pilot PC: a developer tool
// installer rewrote it) gave the tunneler ENOENT for every one of them. The
// tunnel came up, but no name ever resolved to the overlay and every
// application went the old way, with nothing in the tray to say why.
//
// The directories go first so a same-named program elsewhere on PATH cannot
// stand in for powershell.exe or netsh.exe when the tunneler runs as SYSTEM.
func tunnelerEnv(environ []string, systemRoot string) []string {
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	systemRoot = strings.TrimRight(systemRoot, `\/`)
	sys32 := systemRoot + `\System32`
	want := []string{
		sys32,
		systemRoot,
		sys32 + `\Wbem`,
		sys32 + `\WindowsPowerShell\v1.0`,
	}
	out := make([]string, 0, len(environ)+1)
	var rest []string
	found := false
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && strings.EqualFold(k, "PATH") {
			if !found {
				found = true
				rest = strings.Split(v, ";")
			}
			continue
		}
		out = append(out, kv)
	}
	seen := map[string]bool{}
	path := make([]string, 0, len(want)+len(rest))
	for _, d := range append(want, rest...) {
		d = strings.TrimSpace(d)
		key := strings.ToLower(strings.TrimRight(d, `\/`))
		if d == "" || seen[key] {
			continue
		}
		seen[key] = true
		path = append(path, d)
	}
	return append(out, "PATH="+strings.Join(path, ";"))
}
