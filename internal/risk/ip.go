package risk

import "net"

// IsPrivateIP reports whether an address is on a private or link-local range.
//
// It lived in device.go alongside a DeviceFingerprinter nothing constructed,
// and it is the live half: the risk scorer's IP-reputation signal treats a
// private address differently from a public one, because a login from inside
// the network is not the same event as one from the internet.
func IsPrivateIP(ip string) bool {
	// Handle localhost hostname
	if ip == "localhost" {
		return true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		if _, ipNet, _ := net.ParseCIDR(cidr); ipNet != nil && ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}
