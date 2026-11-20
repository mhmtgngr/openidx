package access

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// DARK PUBLISH: an administrator publishes an internal web application in one
// step and the result is reachable only through the agent's tunnel.
//
// Until now that took three calls to three services: the network resource
// (access), who may use it (portal) and whether the device must be trusted
// (admin conditions). The result of getting any one wrong was an application
// nobody could open, or one everybody could. This file turns what a person
// types (an address, who may use it) into the three rows, written together or
// not at all.

// errPublishAddress is what parsePublishAddress and publishDarkApp answer for an
// address that cannot be published: the cause is wrapped, the sentinel is what
// the handler maps to a 400.
var errPublishAddress = errors.New("invalid address")

func publishAddressErr(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", errPublishAddress, fmt.Sprintf(format, args...))
}

// parsePublishAddress reads the address an administrator types ("the address
// people type today") as a network target and the URL a person opens it with.
//
// A value without a scheme is read as https. Only http and https are accepted;
// the default port follows the scheme. A name goes to DNSNames and an IP
// literal to Hosts, tcp only, one port: a published web application is one name
// and one port, which is also what lets the server pin it (network_pins.go).
// The launch URL keeps the path and query, drops the fragment and omits a
// default port. The target is NOT yet normalized or guarded: the caller passes
// it through normalizeNetworkTarget, which refuses the platform's own
// addresses.
func parsePublishAddress(raw string) (NetworkTarget, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return NetworkTarget{}, "", publishAddressErr("the address is empty")
	}
	s := raw
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return NetworkTarget{}, "", publishAddressErr("%q is not an address", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return NetworkTarget{}, "", publishAddressErr("only http and https addresses can be published, not %q", u.Scheme)
	}
	if u.User != nil {
		return NetworkTarget{}, "", publishAddressErr("an address cannot carry a user name or password")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return NetworkTarget{}, "", publishAddressErr("the address has no host")
	}
	if strings.Contains(host, "*") {
		return NetworkTarget{}, "", publishAddressErr("a wildcard cannot be published here; publish one application at a time")
	}

	defaultPort := 443
	if scheme == "http" {
		defaultPort = 80
	}
	port := defaultPort
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n < 1 || n > 65535 {
			return NetworkTarget{}, "", publishAddressErr("the port %q is not between 1 and 65535", p)
		}
		port = n
	}

	target := NetworkTarget{
		PortRanges: []PortRange{{Low: port, High: port}},
		Protocols:  []string{"tcp"},
	}
	hostForURL := host
	if ip := net.ParseIP(host); ip != nil {
		target.Hosts = []string{ip.String()}
		hostForURL = ip.String()
		if ip.To4() == nil {
			hostForURL = "[" + hostForURL + "]"
		}
	} else if validHostName(host) {
		target.DNSNames = []string{host}
	} else {
		return NetworkTarget{}, "", publishAddressErr("%q is neither a host name nor an IP address", host)
	}

	launch := scheme + "://" + hostForURL
	if port != defaultPort {
		launch += ":" + strconv.Itoa(port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	launch += path
	if u.RawQuery != "" {
		launch += "?" + u.RawQuery
	}
	return target, launch, nil
}
