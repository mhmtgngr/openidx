//go:build windows

package plugin

import "fmt"

// checkTrustedPath refuses every path on Windows, and says why.
//
// The Unix half of this check is the file's mode bits. Windows discards them —
// the Go runtime maps 0755 to "not read-only" and nothing else — so the same
// code there would report every path as trusted while checking nothing. That is
// the exact shape this branch keeps finding: a control that returns a pass it
// never earned, in the one place where the process asking is the SERVICE, which
// runs as SYSTEM.
//
// Doing it properly means reading the path's DACL and deciding whether any
// non-privileged SID holds a write right — GetNamedSecurityInfo, then walking
// the ACEs for FILE_WRITE_DATA / FILE_APPEND_DATA / WRITE_DAC / WRITE_OWNER /
// DELETE, resolving group memberships, and treating an inherited-but-unblocked
// ACL correctly. agent/internal/secretfile does the writing half of that for two
// files; there is no reading half, and a version of it written without a Windows
// machine to test against would be either too strict (plugins silently stop
// loading) or too loose (a pass, again, that was never earned).
//
// So this refuses. Nothing in the repository sets plugin_dir — it is read in one
// place and written nowhere, so no shipped configuration is affected — and an
// operator who reaches for it on Windows gets a message naming the missing
// control instead of a privileged process executing a file of unknown
// provenance. When the DACL check exists, this file is what it replaces.
func checkTrustedPath(path string) error {
	return fmt.Errorf("refusing to load plugins from %s: the permission check that "+
		"decides whether a path is safe to execute from is implemented with Unix mode "+
		"bits, which Windows discards, and the equivalent DACL check is not written "+
		"yet. The agent service runs as SYSTEM, so a directory whose writers are "+
		"unknown is not one to execute from. Leave plugin_dir unset on Windows", path)
}
