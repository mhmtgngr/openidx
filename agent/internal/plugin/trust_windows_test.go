//go:build windows

package plugin

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These run on a real Windows runner: windows-client-build.yml runs
// `go test ./...` for the whole agent module. That matters more here than
// anywhere else in this package, because the thing under test is an ACL, and an
// ACL check written against a mental model of Windows rather than Windows is the
// failure this file replaced — trust_windows.go used to refuse every path,
// deliberately, because the check did not exist.
//
// Every fixture sets a PROTECTED DACL, so the ACL under test is exactly the
// entries named and never something the runner's directory happened to inherit.

// sidOrSkip resolves a SID, skipping rather than failing if the machine cannot:
// a runner that cannot name BUILTIN\Users is not a broken check.
func sidOrSkip(t *testing.T, which windows.WELL_KNOWN_SID_TYPE, label string) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(which)
	if err != nil {
		t.Skipf("cannot resolve %s on this machine: %v", label, err)
	}
	return sid
}

// windowsSID re-creates a SID in Windows-allocated memory. TrusteeValueFromSID
// stores the pointer as a uintptr, which the garbage collector cannot see, so a
// SID that lives in Go memory (the one from the process token does) would need
// pinning. Round-tripping it through its string form avoids the whole question.
func windowsSID(t *testing.T, sid *windows.SID) *windows.SID {
	t.Helper()
	out, err := windows.StringToSid(sid.String())
	if err != nil {
		t.Fatalf("re-create %s: %v", sid.String(), err)
	}
	return out
}

type grant struct {
	sid    *windows.SID
	rights uint32
}

// setProtectedDACL replaces path's DACL with exactly these grants, inheritance
// off. Returns after the ACL is in place, so a caller can read it straight back.
func setProtectedDACL(t *testing.T, path string, grants ...grant) {
	t.Helper()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(grants))
	for _, g := range grants {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.ACCESS_MASK(g.rights),
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(windowsSID(t, g.sid)),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("build DACL for %s: %v", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("apply DACL to %s: %v", path, err)
	}
}

// privileged returns the grants a correctly-locked-down path carries: SYSTEM,
// Administrators, and the account running the test (which is what the service
// running as SYSTEM reduces to in production).
func privileged(t *testing.T) []grant {
	t.Helper()
	self, err := currentProcessSID()
	if err != nil {
		t.Fatalf("current process SID: %v", err)
	}
	return []grant{
		{sidOrSkip(t, windows.WinLocalSystemSid, "SYSTEM"), windows.GENERIC_ALL},
		{sidOrSkip(t, windows.WinBuiltinAdministratorsSid, "BUILTIN\\Administrators"), windows.GENERIC_ALL},
		{self, windows.GENERIC_ALL},
	}
}

// TestAPrivilegedOnlyPathIsTrusted. Without this, "refuses everything" would
// pass every other test in this file — which is exactly what the previous
// implementation did, and why this one has to prove it can say yes.
func TestAPrivilegedOnlyPathIsTrusted(t *testing.T) {
	dir := t.TempDir()
	setProtectedDACL(t, dir, privileged(t)...)

	if err := checkTrustedPath(dir); err != nil {
		t.Fatalf("a directory writable only by SYSTEM, Administrators and this process was "+
			"refused: %v\n\nA check that cannot say yes is a check nobody keeps.", err)
	}
}

// TestAWritableGrantToAnUnprivilegedGroupIsRefused is the finding itself. Each
// right here is on its own enough to replace what the agent executes.
func TestAWritableGrantToAnUnprivilegedGroupIsRefused(t *testing.T) {
	users := sidOrSkip(t, windows.WinBuiltinUsersSid, "BUILTIN\\Users")
	everyone := sidOrSkip(t, windows.WinWorldSid, "Everyone")

	for _, tc := range []struct {
		name   string
		sid    *windows.SID
		rights uint32
		why    string
	}{
		{"Users, full control", users, windows.GENERIC_ALL, "the %ProgramData% default this branch already fixed for secret files"},
		{"Users, generic write", users, windows.GENERIC_WRITE, "enough to overwrite the plugin"},
		{"Users, write data", users, windows.FILE_WRITE_DATA, "the specific right, unmapped"},
		{"Users, delete", users, windows.DELETE, "delete it and put your own there"},
		{"Users, delete child", users, fileDeleteChild, "on a directory, deletes an entry whatever that entry's own ACL says"},
		{"Users, change permissions", users, windows.WRITE_DAC, "one call away from every other right"},
		{"Users, take ownership", users, windows.WRITE_OWNER, "two calls away"},
		{"Everyone, full control", everyone, windows.GENERIC_ALL, "the widest form of the same thing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			setProtectedDACL(t, dir, append(privileged(t), grant{tc.sid, tc.rights})...)

			err := checkTrustedPath(dir)
			if err == nil {
				t.Fatalf("a directory granting %s to an unprivileged group was reported as safe to "+
					"execute from (%s). The agent service runs as SYSTEM.", tc.name, tc.why)
			}
			// The message has to name who, or an operator cannot fix it.
			if !strings.Contains(err.Error(), "Users") && !strings.Contains(err.Error(), "Everyone") {
				t.Errorf("the refusal does not name the principal that holds the right: %v", err)
			}
		})
	}
}

// TestReadAndExecuteForEveryoneIsStillTrusted. The check must distinguish "can
// read what runs" from "can change what runs" — %ProgramFiles% grants Users
// read and execute on every Windows install, and a check that refused that
// would refuse the ordinary installation directory and be turned off.
func TestReadAndExecuteForEveryoneIsStillTrusted(t *testing.T) {
	users := sidOrSkip(t, windows.WinBuiltinUsersSid, "BUILTIN\\Users")

	dir := t.TempDir()
	setProtectedDACL(t, dir, append(privileged(t),
		grant{users, windows.GENERIC_READ | windows.GENERIC_EXECUTE})...)

	if err := checkTrustedPath(dir); err != nil {
		t.Fatalf("a directory granting Users read and execute — the %%ProgramFiles%% default — "+
			"was refused: %v", err)
	}
}

// TestTrustedInstallerMayHoldFullControl, for the same reason: it owns
// %ProgramFiles% content on every install, and it is more privileged than the
// account asking, not less.
func TestTrustedInstallerMayHoldFullControl(t *testing.T) {
	ti, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		t.Skipf("cannot resolve TrustedInstaller: %v", err)
	}
	dir := t.TempDir()
	setProtectedDACL(t, dir, append(privileged(t), grant{ti, windows.GENERIC_ALL})...)

	if err := checkTrustedPath(dir); err != nil {
		t.Fatalf("TrustedInstaller holding full control was treated as untrusted: %v", err)
	}
}

// TestAPathThatCannotBeReadIsRefused: the check must not report a path it could
// not inspect as safe.
func TestAPathThatCannotBeReadIsRefused(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-directory")
	if err := checkTrustedPath(missing); err == nil {
		t.Error("a path whose security descriptor cannot be read was reported as trusted")
	}
}

// TestDangerousRightsCoverEveryWriteShapedRight guards the mask itself. It is a
// list of constants, and a list is the thing that silently loses an entry.
func TestDangerousRightsCoverEveryWriteShapedRight(t *testing.T) {
	for _, r := range []struct {
		bit  uint32
		name string
	}{
		{windows.FILE_WRITE_DATA, "FILE_WRITE_DATA"},
		{windows.FILE_APPEND_DATA, "FILE_APPEND_DATA"},
		{fileDeleteChild, "FILE_DELETE_CHILD"},
		{windows.DELETE, "DELETE"},
		{windows.WRITE_DAC, "WRITE_DAC"},
		{windows.WRITE_OWNER, "WRITE_OWNER"},
		{windows.GENERIC_WRITE, "GENERIC_WRITE"},
		{windows.GENERIC_ALL, "GENERIC_ALL"},
	} {
		if dangerousRights&r.bit == 0 {
			t.Errorf("%s is not in dangerousRights: an ACE granting only that right would be "+
				"reported as harmless, and it lets its holder change what the agent executes", r.name)
		}
		// describeRights always returns something — it falls back to the raw
		// mask — so asserting non-empty would assert nothing. The claim is that
		// it NAMES the right, which is what an operator needs to fix it.
		if got := describeRights(r.bit); strings.HasPrefix(got, "mask ") {
			t.Errorf("describeRights(%s) fell back to %q instead of naming the right; the refusal "+
				"would tell an operator a hexadecimal number", r.name, got)
		}
	}

	// And the read side must NOT be in it, or the check refuses every ordinary
	// installation directory.
	for _, r := range []struct {
		bit  uint32
		name string
	}{
		{windows.FILE_READ_DATA, "FILE_READ_DATA"},
		{windows.FILE_EXECUTE, "FILE_EXECUTE"},
		{windows.READ_CONTROL, "READ_CONTROL"},
		{windows.SYNCHRONIZE, "SYNCHRONIZE"},
	} {
		if dangerousRights&r.bit != 0 {
			t.Errorf("%s counts as dangerous, so a path that merely lets users RUN the agent "+
				"would be refused", r.name)
		}
	}
}
