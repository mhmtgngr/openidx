package sso

import (
	"os/exec"
	"runtime"
)

// OpenURL opens url in the user's default browser (best-effort). Exported for
// reuse by the PAM launch path.
func OpenURL(url string) error { return openBrowser(url) }

// openBrowser opens url in the user's default browser (best-effort).
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
