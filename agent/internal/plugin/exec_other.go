//go:build !windows

package plugin

import "io/fs"

// executableNames are the file names a plugin's executable may have: the plain
// name a compiled binary carries, and the .sh a script one does.
func executableNames(base string) []string {
	return []string{base, base + ".sh"}
}

// isRunnable: the execute bit is the answer here, for owner, group or other.
// Whether the file is safe to run is a different question, and requireTrustedPath
// is where it is asked.
func isRunnable(info fs.FileInfo) bool {
	return info.Mode()&0o111 != 0
}
