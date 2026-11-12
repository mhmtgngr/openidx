//go:build windows

package tray

import "golang.org/x/sys/windows"

var procGetUserDefaultUILanguage = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

// uiLanguage is the user's Windows display language (a LANGID), or 0.
func uiLanguage() uint16 {
	if procGetUserDefaultUILanguage.Find() != nil {
		return 0
	}
	r, _, _ := procGetUserDefaultUILanguage.Call()
	return uint16(r)
}
