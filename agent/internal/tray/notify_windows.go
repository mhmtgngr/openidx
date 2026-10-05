//go:build windows

package tray

import (
	"golang.org/x/sys/windows"
)

// tell shows msg to the person at the device in a message box. It blocks the
// calling goroutine until they dismiss it, so callers run it off the menu
// loop. A failed string conversion only drops the box; the logger already has
// the error.
func (a *app) tell(msg string) {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	caption, err := windows.UTF16PtrFromString("OpenIDX")
	if err != nil {
		return
	}
	_, _ = windows.MessageBox(0, text, caption,
		windows.MB_OK|windows.MB_ICONWARNING|windows.MB_SETFOREGROUND|windows.MB_TOPMOST)
}
