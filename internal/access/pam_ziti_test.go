package access

import "testing"

func TestAllocateLoopbackPort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		used []int
		base int
		max  int
		want int
	}{
		{"empty picks base", nil, 14000, 14999, 14000},
		{"skips taken prefix", []int{14000, 14001}, 14000, 14999, 14002},
		{"fills lowest gap", []int{14000, 14002}, 14000, 14999, 14001},
		{"out-of-window used ignored", []int{22, 3389}, 14000, 14999, 14000},
		{"exhausted returns 0", []int{14000, 14001}, 14000, 14001, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := allocateLoopbackPort(tc.used, tc.base, tc.max); got != tc.want {
				t.Fatalf("allocateLoopbackPort(%v,%d,%d) = %d, want %d", tc.used, tc.base, tc.max, got, tc.want)
			}
		})
	}
}

// The whole point of ziti reach: in ziti mode guacd must dial the broker's
// loopback intercept, never the real target; direct mode dials the target.
func TestPamLaunchEntryDialTarget(t *testing.T) {
	t.Parallel()

	direct := pamLaunchEntry{Hostname: "dc01.corp", Port: 3389, ReachMode: "direct"}
	if h, p := direct.dialTarget(); h != "dc01.corp" || p != 3389 {
		t.Fatalf("direct dialTarget = %s:%d, want dc01.corp:3389", h, p)
	}

	ziti := pamLaunchEntry{Hostname: "dc01.corp", Port: 3389, ReachMode: "ziti", ZitiInterceptPort: 14007}
	if h, p := ziti.dialTarget(); h != "127.0.0.1" || p != 14007 {
		t.Fatalf("ziti dialTarget = %s:%d, want 127.0.0.1:14007 — target must NOT be dialed directly", h, p)
	}

	// A ziti entry with no assigned intercept port must fall back to the real
	// target rather than dial 127.0.0.1:0.
	broken := pamLaunchEntry{Hostname: "dc01.corp", Port: 3389, ReachMode: "ziti", ZitiInterceptPort: 0}
	if h, p := broken.dialTarget(); h != "dc01.corp" || p != 3389 {
		t.Fatalf("ziti-without-port dialTarget = %s:%d, want fallback dc01.corp:3389", h, p)
	}
}

func TestPamZitiServiceName(t *testing.T) {
	t.Parallel()

	got := pamZitiServiceName("abc-123")
	if got != "openidx-pam-abc-123" {
		t.Fatalf("pamZitiServiceName = %q", got)
	}
	// The service name must carry the openidx- prefix TeardownZitiServiceByName
	// keys its openidx-bind-/openidx-dial-/openidx-serp- cleanup off.
	if got[:8] != "openidx-" {
		t.Fatalf("service name %q lacks openidx- prefix required for teardown", got)
	}
}
