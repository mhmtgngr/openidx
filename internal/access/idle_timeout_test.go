package access

import (
	"testing"
	"time"
)

func TestIsIdleExpired(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		route   *ProxyRoute
		session *ProxySession
		want    bool
	}{
		{
			name:    "idle beyond timeout -> expired",
			route:   &ProxyRoute{IdleTimeout: 900},
			session: &ProxySession{LastActiveAt: now.Add(-1000 * time.Second)},
			want:    true,
		},
		{
			name:    "active within window -> not expired",
			route:   &ProxyRoute{IdleTimeout: 900},
			session: &ProxySession{LastActiveAt: now.Add(-10 * time.Second)},
			want:    false,
		},
		{
			name:    "exactly at boundary -> not expired (strictly greater)",
			route:   &ProxyRoute{IdleTimeout: 900},
			session: &ProxySession{LastActiveAt: now.Add(-900 * time.Second)},
			want:    false,
		},
		{
			name:    "idle_timeout disabled (0) -> never idle-expires",
			route:   &ProxyRoute{IdleTimeout: 0},
			session: &ProxySession{LastActiveAt: now.Add(-100000 * time.Second)},
			want:    false,
		},
		{
			name:    "no last-active stamp -> rides absolute expiry",
			route:   &ProxyRoute{IdleTimeout: 900},
			session: &ProxySession{}, // zero LastActiveAt
			want:    false,
		},
		{
			name:    "nil route -> false",
			route:   nil,
			session: &ProxySession{LastActiveAt: now.Add(-100000 * time.Second)},
			want:    false,
		},
		{
			name:    "nil session -> false",
			route:   &ProxyRoute{IdleTimeout: 900},
			session: nil,
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isIdleExpired(tc.route, tc.session, now); got != tc.want {
				t.Fatalf("isIdleExpired = %v, want %v", got, tc.want)
			}
		})
	}
}
