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

// ask puts a yes/no question to the person at the device and blocks until
// they answer. No is the default button, so an accidental Enter changes
// nothing.
func (a *app) ask(msg string) bool {
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return false
	}
	caption, err := windows.UTF16PtrFromString("OpenIDX")
	if err != nil {
		return false
	}
	ret, err := windows.MessageBox(0, text, caption,
		windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_DEFBUTTON2|windows.MB_SETFOREGROUND|windows.MB_TOPMOST)
	return err == nil && ret == idYesButton
}

// idYesButton is MessageBox's return value for Yes.
const idYesButton = 6
