//go:build windows

package checks

import (
	"context"
	"testing"
	"time"
)

// The Windows implementations of the posture checks shell out to manage-bde,
// netsh, PowerShell and WMI and parse what comes back. The cross-platform
// test suite runs on Linux, where every one of them answers "not supported on
// linux" before any of that code runs, so a parser that broke on a real
// Windows answer was never caught. This file runs on the Windows runner (the
// build-msi job selects every //go:build windows test function) and exercises
// each Windows path against the host it runs on.
//
// The assertions are about shape, not about the runner's configuration: a
// GitHub-hosted Windows image has BitLocker off and Defender in whatever state
// the image ships, and that may change. What must hold is that the Windows
// code path ran (the result is not marked Unsupported), it did not panic, it
// finished in bounded time, and it produced a status in the known set with a
// message a person could read.

func TestEveryWindowsCheckRunsOnThisHost(t *testing.T) {
	known := map[Status]bool{StatusPass: true, StatusFail: true, StatusWarn: true, StatusError: true}
	cases := []struct {
		name   string
		check  Check
		params map[string]interface{}
	}{
		{"os_version", &OSVersionCheck{}, map[string]interface{}{"min_version": "10.0"}},
		{"disk_encryption", &DiskEncryptionCheck{}, nil},
		{"firewall", &FirewallCheck{}, nil},
		{"antivirus", &AntivirusCheck{}, nil},
		{"screen_lock", &ScreenLockCheck{}, nil},
		{"domain_joined", &DomainCheck{}, nil},
		{"patch_level", &PatchLevelCheck{}, map[string]interface{}{"max_days": 3650}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			res := tc.check.Run(ctx, tc.params)
			if res == nil {
				t.Fatal("nil result")
			}
			if res.Unsupported {
				t.Fatalf("the Windows implementation must run on Windows; got Unsupported with %q", res.Message)
			}
			if !known[res.Status] {
				t.Fatalf("status %q is not one of pass/fail/warn/error", res.Status)
			}
			if res.Message == "" {
				t.Fatal("a result with no message tells the operator nothing")
			}
			if res.Score < 0 || res.Score > 1 {
				t.Fatalf("score %v is outside 0..1", res.Score)
			}
			t.Logf("%s: %s (score %.2f): %s", tc.name, res.Status, res.Score, res.Message)
		})
	}
}

// TestTheOSVersionCheckReadsARealVersionOnWindows is the one check whose
// answer on a Windows runner is known: the host is Windows 10 or Server 2019
// or newer, so a 10.0 minimum passes and a 99.0 minimum fails. That proves the
// `ver` output was parsed, not merely that something ran.
func TestTheOSVersionCheckReadsARealVersionOnWindows(t *testing.T) {
	ctx := context.Background()
	if res := (&OSVersionCheck{}).Run(ctx, map[string]interface{}{"min_version": "10.0"}); res.Status != StatusPass {
		t.Fatalf("a Windows runner must pass a 10.0 minimum; got %s: %s", res.Status, res.Message)
	}
	if res := (&OSVersionCheck{}).Run(ctx, map[string]interface{}{"min_version": "99.0"}); res.Status != StatusFail {
		t.Fatalf("no Windows passes a 99.0 minimum; got %s: %s", res.Status, res.Message)
	}
}
