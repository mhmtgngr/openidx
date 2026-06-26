package risk

import "testing"

func TestComputeDeviceFingerprint_FreeFuncMatchesMethod(t *testing.T) {
	cases := []struct{ ip, ua string }{
		{"192.168.1.10", "Mozilla/5.0 (X11; Linux x86_64)"},
		{"10.0.0.5", "curl/8.0"},
		{"", ""},
		{"not-an-ip", "UA"},
	}
	var s Service
	for _, c := range cases {
		free := ComputeDeviceFingerprint(c.ip, c.ua)
		method := s.ComputeDeviceFingerprint(c.ip, c.ua)
		if free != method {
			t.Errorf("free(%q,%q)=%s != method=%s", c.ip, c.ua, free, method)
		}
		if len(free) != 64 {
			t.Errorf("expected 64-hex sha256, got %d chars: %s", len(free), free)
		}
	}
}

func TestComputeDeviceFingerprint_Subnet(t *testing.T) {
	// Same /24 → same fingerprint (subnet is collapsed to x.y.z.0/24).
	a := ComputeDeviceFingerprint("192.168.1.10", "UA")
	b := ComputeDeviceFingerprint("192.168.1.250", "UA")
	if a != b {
		t.Errorf("same /24 should match: %s != %s", a, b)
	}
	// Different /24 → different.
	if c := ComputeDeviceFingerprint("192.168.2.10", "UA"); a == c {
		t.Error("different /24 should differ")
	}
	// Different UA → different.
	if d := ComputeDeviceFingerprint("192.168.1.10", "OtherUA"); a == d {
		t.Error("different UA should differ")
	}
}
