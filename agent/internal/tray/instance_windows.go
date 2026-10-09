//go:build windows

package tray

import (
	"errors"

	"golang.org/x/sys/windows"
)

// trayMutexName is per session ("Local\"), so each signed-in person gets one
// tray and no privilege is needed to create it.
const trayMutexName = `Local\OpenIDXTray`

// acquireTrayMutex claims the session's single tray slot. The Run key, the
// service and the Start-menu shortcut can all start a tray in the same
// session; every one after the first sees ok=false and exits.
func acquireTrayMutex() (release func(), ok bool) {
	name, err := windows.UTF16PtrFromString(trayMutexName)
	if err != nil {
		return func() {}, true
	}
	h, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return nil, false
	}
	if err != nil {
		// Not being able to tell is no reason to show no tray at all.
		return func() {}, true
	}
	return func() { windows.CloseHandle(h) }, true
}
