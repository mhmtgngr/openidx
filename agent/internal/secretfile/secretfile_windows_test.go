//go:build windows

package secretfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The Windows half, which is the half that was missing. These cases run only on
// a Windows runner: .github/workflows/windows-client-build.yml runs the agent's
// `go test ./...` on ubuntu-latest, where every one of them is compiled out, so
// the same workflow's windows-latest job runs this package's tests natively.
// Without that step these would be tests nothing executes — the defect class
// this branch has spent its time deleting.

// TestFileIsEncryptedAtRest: the bytes on disk must not be the secret.
func TestFileIsEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-tokens.json")
	secret := []byte(`{"refresh_token":"a-thirty-day-credential"}`)

	if err := Write(path, secret); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !IsProtected(raw) {
		t.Fatal("the file carries no DPAPI marker; it was written in the clear")
	}
	if strings.Contains(string(raw), "a-thirty-day-credential") {
		t.Error("the refresh token is readable in the file's bytes")
	}

	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("round trip returned %q", got)
	}
}

// TestCorruptBlobIsAnError: a truncated or tampered DPAPI blob must fail loudly
// rather than hand the caller a fragment to parse.
func TestCorruptBlobIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-tokens.json")
	if err := Write(path, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the ciphertext.
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Read(path); err == nil {
		t.Error("a tampered blob decrypted without error")
	}
}

// TestDACLIsExplicitAndNotInherited is the finding itself: the file used to
// inherit %ProgramData%'s permissions, where BUILTIN\Users can read. After
// Write the DACL must be protected (inheritance off), must not name Users, and
// must still name the account that wrote it — or the agent has locked itself
// out of its own session.
//
// Read as SDDL, which is the form a support engineer will compare against
// `icacls` output: SY is NT AUTHORITY\SYSTEM, BA is BUILTIN\Administrators,
// BU is BUILTIN\Users, and "P" in the control flags means the DACL is
// protected from inheritance.
func TestDACLIsExplicitAndNotInherited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-endpoint.json")
	if err := Write(path, []byte(`{"token":"drives-the-engine"}`)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	sddl := sd.String()

	dacl := sddl
	if i := strings.Index(sddl, "D:"); i >= 0 {
		dacl = sddl[i:]
	}
	if !strings.HasPrefix(dacl, "D:P") {
		t.Errorf("the DACL is not protected from inheritance, so %%ProgramData%%'s ACEs still apply: %s", sddl)
	}
	if strings.Contains(dacl, ";BU)") {
		t.Errorf("BUILTIN\\Users is still granted access to the secret file: %s", sddl)
	}
	for _, who := range []string{";SY)", ";BA)"} {
		if !strings.Contains(dacl, who) {
			t.Errorf("the DACL does not grant %s (SYSTEM and Administrators must keep access): %s", who, sddl)
		}
	}

	self, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	// Compare on the token Windows itself uses for this SID, not on the SID
	// string. SDDL abbreviates well-known accounts to two-letter aliases, and
	// on a runner whose user is the built-in Administrator (RID 500) the ACE
	// reads ";LA)" while self.String() is the full S-1-5-21-…-500 — so a
	// substring match reports the writer as absent from a DACL that names them.
	// That is what happened the first time this job ran on Windows: a correct
	// ACL, a test comparing two spellings of the same principal.
	want, err := sddlToken(self)
	if err != nil {
		t.Fatalf("render %s as SDDL: %v", self.String(), err)
	}
	if !strings.Contains(dacl, ";"+want+")") {
		t.Errorf("the writing user (%s, rendered %q) is not in the DACL: %s", self.String(), want, sddl)
	}
}

// sddlToken asks Windows how it spells this SID inside an ACE, by round-
// tripping a one-ACE descriptor through the same conversion that produced the
// string under test. A well-known account comes back as its alias, anything
// else as its SID, so the comparison is like for like whoever runs the job.
func sddlToken(sid *windows.SID) (string, error) {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")")
	if err != nil {
		return "", err
	}
	s := sd.String()
	close := strings.LastIndex(s, ")")
	if close < 0 {
		return "", fmt.Errorf("unexpected descriptor %q", s)
	}
	semi := strings.LastIndex(s[:close], ";")
	if semi < 0 {
		return "", fmt.Errorf("unexpected descriptor %q", s)
	}
	return s[semi+1 : close], nil
}
