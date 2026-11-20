package access

import (
	"errors"
	"reflect"
	"testing"
)

func TestParsePublishAddress(t *testing.T) {
	ok := []struct {
		in       string
		wantName string
		wantHost string
		wantPort int
		wantURL  string
	}{
		{"https://wiki.corp.example", "wiki.corp.example", "", 443, "https://wiki.corp.example/"},
		{"  HTTPS://Wiki.Corp.Example/docs?x=1 ", "wiki.corp.example", "", 443, "https://wiki.corp.example/docs?x=1"},
		{"http://intranet.corp.example", "intranet.corp.example", "", 80, "http://intranet.corp.example/"},
		{"wiki.corp.example", "wiki.corp.example", "", 443, "https://wiki.corp.example/"},
		{"wiki.corp.example:8443", "wiki.corp.example", "", 8443, "https://wiki.corp.example:8443/"},
		{"https://198.51.100.20:8443", "", "198.51.100.20", 8443, "https://198.51.100.20:8443/"},
		{"wiki.corp.example.", "wiki.corp.example", "", 443, "https://wiki.corp.example/"},
		{"https://wiki.corp.example:443/a#frag", "wiki.corp.example", "", 443, "https://wiki.corp.example/a"},
	}
	for _, tc := range ok {
		t.Run(tc.in, func(t *testing.T) {
			target, launch, err := parsePublishAddress(tc.in)
			if err != nil {
				t.Fatalf("parsePublishAddress(%q): %v", tc.in, err)
			}
			var wantNames, wantHosts []string
			if tc.wantName != "" {
				wantNames = []string{tc.wantName}
			}
			if tc.wantHost != "" {
				wantHosts = []string{tc.wantHost}
			}
			if !reflect.DeepEqual(target.DNSNames, wantNames) || !reflect.DeepEqual(target.Hosts, wantHosts) {
				t.Errorf("names=%v hosts=%v, want names=%v hosts=%v", target.DNSNames, target.Hosts, wantNames, wantHosts)
			}
			if !reflect.DeepEqual(target.PortRanges, []PortRange{{Low: tc.wantPort, High: tc.wantPort}}) {
				t.Errorf("port ranges = %v, want one range at %d", target.PortRanges, tc.wantPort)
			}
			if !reflect.DeepEqual(target.Protocols, []string{"tcp"}) {
				t.Errorf("protocols = %v, want tcp only", target.Protocols)
			}
			if len(target.CIDRs) != 0 || target.ForwardAddress != "" || target.ForwardPort != 0 {
				t.Errorf("cidrs=%v forward=%q:%d, want none", target.CIDRs, target.ForwardAddress, target.ForwardPort)
			}
			if launch != tc.wantURL {
				t.Errorf("launch URL = %q, want %q", launch, tc.wantURL)
			}
		})
	}

	bad := []string{"", "   ", "ftp://files.corp.example", "https://", "https://*.corp.example",
		"https://user:pw@wiki.corp.example", "wiki.corp.example:0", "wiki.corp.example:70000",
		"https://wiki.corp.example:abc", "two words.example"}
	for _, in := range bad {
		t.Run("bad "+in, func(t *testing.T) {
			_, _, err := parsePublishAddress(in)
			if err == nil || !errors.Is(err, errPublishAddress) {
				t.Fatalf("parsePublishAddress(%q) = %v, want errPublishAddress", in, err)
			}
		})
	}
}
