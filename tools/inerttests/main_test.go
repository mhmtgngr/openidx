package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Every case is a shape that exists (or plausibly exists) in this tree. The
// negative cases matter more than the positive ones: a guard that reddens on a
// legitimate test is a guard somebody deletes, and three of the four shapes
// below LOOK inert at a glance and are not.
func TestScan(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			// Verbatim internal/directory/service_test.go:1257. A method VALUE
			// assigned to _, under a comment saying it "checks the method exists
			// and has proper signature" — which the compiler does.
			name: "a method value assigned to the blank identifier",
			src: `package p
import "testing"
func TestService_AuthenticateUser_UnsupportedType(t *testing.T) {
	service := &Service{}
	ctx := context.Background()
	// We test the error path by checking the method exists
	_ = service.AuthenticateUser
	_ = ctx
}`,
			want: 1,
		},
		{
			// Verbatim internal/server/graceful_test.go:499 — builds the server
			// and never calls the function the test is named after.
			name: "a test named after a function it never calls",
			src: `package p
import "testing"
func TestListenAndServe(t *testing.T) {
	gs := New(Config{})
	// This would normally block, but we'll just verify it doesn't panic
	_ = gs
}`,
			want: 1,
		},
		{
			// A CALL assigned to _ runs code. internal/auth/roles_test.go does
			// this deliberately to prove the methods are nil-safe: if one panics
			// the test fails. Reporting it would be wrong.
			name: "a call assigned to the blank identifier still runs",
			src: `package p
import "testing"
func TestRoleMethodsNilSafety(t *testing.T) {
	var zeroRole Role
	_ = zeroRole.Level()
	_ = zeroRole.Inherits(RoleAdmin)
}`,
			want: 0,
		},
		{
			// The compile-time interface assertion. It is a declaration, not an
			// assignment, and it is exactly the right way to pin a contract.
			name: "a compile-time interface assertion",
			src: `package p
import "testing"
func TestOrgLookup_implementsMiddlewareInterface(t *testing.T) {
	var _ middleware.OrgLookup = NewOrgLookup(&fakeFetcher{})
}`,
			want: 0,
		},
		{
			// An ordinary test. The blank assignment is discarding a return
			// value it does not need, which is not the same as doing nothing.
			name: "a real test that happens to discard one result",
			src: `package p
import "testing"
func TestSomethingReal(t *testing.T) {
	got, _ := Parse("x")
	if got != "x" {
		t.Fatalf("got %q", got)
	}
}`,
			want: 0,
		},
		{
			// The escape hatch, with a reason.
			name: "a reasoned ignore directive suppresses the finding",
			src: `package p
import "testing"

//inerttests:ignore the linker drops unused symbols; this pins the symbol only
func TestSymbolIsLinked(t *testing.T) {
	_ = SomeExportedVar
}`,
			want: 0,
		},
		{
			// ...and without one it suppresses nothing, so an exception cannot
			// slip in unexplained.
			name: "a reason-less ignore directive suppresses nothing",
			src: `package p
import "testing"

//inerttests:ignore
func TestSymbolIsLinked(t *testing.T) {
	_ = SomeExportedVar
}`,
			want: 1,
		},
		{
			// A body with no blank assignment at all is simply not this shape,
			// however little it asserts — a skipping test belongs to
			// scripts/check-inert-tests.sh, not here.
			//
			// The skip is CONDITIONAL on purpose. An unconditional one written
			// out in full here would be matched by that other guard scanning
			// this very file, and a fixture is not a finding: the two guards
			// have to be able to describe each other's shapes without tripping
			// over them.
			name: "a body with no blank assignment is not this shape",
			src: `package p
import "testing"
func TestNeedsADatabase(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("no database")
	}
	assertThings(t)
}`,
			want: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "a_test.go"), []byte(tc.src), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			got, scanned, err := scan(dir)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if scanned != 1 {
				t.Fatalf("scanned %d files, want 1", scanned)
			}
			if len(got) != tc.want {
				t.Fatalf("findings = %d, want %d: %+v", len(got), tc.want, got)
			}
		})
	}
}

// A guard that greens on an empty scan is how a check ends up wired to the
// wrong directory and nobody notices for a release.
func TestScanReportsAnEmptyTree(t *testing.T) {
	_, scanned, err := scan(t.TempDir())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scanned != 0 {
		t.Fatalf("scanned %d files in an empty tree, want 0", scanned)
	}
}
