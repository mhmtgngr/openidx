//go:build windows

package doctor

import "golang.org/x/sys/windows"

var procGetUserDefaultUILanguage = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

// DetectLang follows the user's Windows display language: Turkish for any
// Turkish locale (primary language id 0x1f), English otherwise.
func DetectLang() Lang {
	if procGetUserDefaultUILanguage.Find() != nil {
		return LangEN
	}
	r, _, _ := procGetUserDefaultUILanguage.Call()
	if uint16(r)&0x3ff == 0x1f {
		return LangTR
	}
	return LangEN
}
