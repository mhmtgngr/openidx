//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// swShowNormal is ShellExecute's "show the window" flag (SW_SHOWNORMAL).
const swShowNormal = 1

// elevateForDeepLink hands an openidx:// link to an elevated copy of this
// program when the current one is not elevated. The browser opens the link in
// the user's own context; enrolment writes %ProgramData%\OpenIDX\agent\agent.json,
// which only SYSTEM and administrators may write, and starts the service.
// handedOff true means the caller must exit: either the elevated copy is
// doing the work, or the person declined the prompt (err says so).
func elevateForDeepLink(link string) (handedOff bool, err error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return true, fmt.Errorf("locating the agent: %w", err)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return true, err
	}
	args, err := windows.UTF16PtrFromString(`"` + link + `"`)
	if err != nil {
		return true, err
	}
	if err := windows.ShellExecute(0, verb, file, args, nil, swShowNormal); err != nil {
		return true, fmt.Errorf("administrator approval was declined or could not be requested: %w", err)
	}
	return true, nil
}

// notifyDeepLink shows the outcome of a link-started enrolment. The process
// was started by the OS, not from a console, so printing would reach nobody.
func notifyDeepLink(msg string) {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	caption, _ := windows.UTF16PtrFromString("OpenIDX")
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND|windows.MB_TOPMOST)
}
