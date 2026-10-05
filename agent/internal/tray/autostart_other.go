//go:build !windows

package tray

// AutostartDisabled is always false off Windows: there is no tray to start.
func AutostartDisabled() bool { return false }

func setAutostart(bool) error { return nil }
