//go:build windows

package plugin

import "io/fs"

// executableNames are the file names a plugin's executable may have on Windows.
//
// The extension is what makes a file runnable here — there is no execute bit —
// so a bare name with no extension is deliberately NOT a candidate: Windows
// would not run it, and accepting it would hand exec.Command a path that fails
// at launch instead of being skipped with a reason. .sh is not a candidate for
// the same reason.
func executableNames(base string) []string {
	return []string{base + ".exe", base + ".bat", base + ".cmd"}
}

// isRunnable: on Windows the name above already decided it.
//
// Not the file mode. Go synthesises a mode on Windows from the read-only
// attribute, so an ordinary file reads as 0666 and `mode&0111` is zero for
// every executable on the system — which is precisely why the previous version
// of this check found no plugin on Windows, ever.
func isRunnable(fs.FileInfo) bool { return true }
