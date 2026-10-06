//go:build windows

package tray

import (
	"golang.org/x/sys/windows/registry"
)

// autostartKey is the per-user preference. The MSI's Run key is machine-wide
// (HKLM) and starts the tray for every user with --autostart; this value is
// how one user opts out without touching the others.
const (
	autostartKey   = `Software\OpenIDX\Agent`
	autostartValue = "TrayAutostart"
)

// AutostartDisabled reports whether this user turned "Start when I sign in"
// off. Absent means on.
func AutostartDisabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, autostartKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(autostartValue)
	return err == nil && v == 0
}

// setAutostart records the preference for this user.
func setAutostart(enabled bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, autostartKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	var v uint32
	if enabled {
		v = 1
	}
	return k.SetDWordValue(autostartValue, v)
}
