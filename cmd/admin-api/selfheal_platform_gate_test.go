package main

import (
	"os"
	"strings"
	"testing"
)

// The self-heal panel is mounted here, not by internal/admin's RegisterRoutes,
// so internal/admin's route test (TestInstallWideSettingsNeedAPlatformAdministrator)
// mounts it with the gates this file passes. That test can only be as good as
// the copy, so the copy is pinned: the call must hand SelfHealRoutes the
// platform-administrator gate, because the loop's mode, kill switch and sweep
// act on the whole install and selfheal:manage is a permission an organization
// can grant itself.
func TestSelfHealMutationsNeedAPlatformAdministrator(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(src)
	const call = "adminhandlers.SelfHealRoutes("
	start := strings.Index(body, call)
	if start < 0 {
		t.Fatalf("main.go no longer calls %s; this test pins what that call passes", call)
	}
	depth, end := 0, -1
	for i := start + len(call) - 1; i < len(body); i++ {
		switch body[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		t.Fatalf("could not find the end of the %s call", call)
	}
	if args := body[start : end+1]; !strings.Contains(args, "middleware.RequirePlatformAdmin(") {
		t.Errorf("the self-heal panel is mounted without the platform-administrator gate:\n%s", args)
	}
}
