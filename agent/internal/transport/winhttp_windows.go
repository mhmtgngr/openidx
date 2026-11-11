//go:build windows

package transport

import "golang.org/x/sys/windows/registry"

// machineProxy reads the WinHTTP machine proxy; nil when unset or unreadable.
func machineProxy() *winHTTPProxy {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue("WinHttpSettings")
	if err != nil {
		return nil
	}
	p, err := parseWinHTTPSettings(b)
	if err != nil {
		return nil
	}
	return p
}
