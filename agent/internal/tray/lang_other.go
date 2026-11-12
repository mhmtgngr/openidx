//go:build !windows

package tray

// uiLanguage is 0 off Windows, which selects English.
func uiLanguage() uint16 { return 0 }
