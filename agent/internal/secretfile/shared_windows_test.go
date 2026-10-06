//go:build windows

package secretfile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestASharedFileIsReadableByUsersAndWritableOnlyByTheServiceAndAdmins reads
// the DACL hardenShared sets back from the file: Authenticated Users carry no
// write, delete, WRITE_DAC or WRITE_OWNER right; SYSTEM and Administrators
// carry full control; nothing is inherited.
func TestASharedFileIsReadableByUsersAndWritableOnlyByTheServiceAndAdmins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := WriteShared(path, []byte(`{"server_url":"https://openidx.test"}`)); err != nil {
		t.Fatalf("WriteShared: %v", err)
	}
	got, err := Read(path)
	if err != nil || string(got) != `{"server_url":"https://openidx.test"}` {
		t.Fatalf("Read after WriteShared: %q, %v", got, err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	if ctrl, _, err := sd.Control(); err != nil {
		t.Fatalf("Control: %v", err)
	} else if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the DACL must be protected, or the %ProgramData% ACL flows back in")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	users, _ := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)

	const writeBits = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
		windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
	var sawUsers, sawSystem, sawAdmins bool
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			t.Fatalf("ACE %d is inherited; the file's own list must be the whole list", i)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		mask := uint32(ace.Mask)
		switch {
		case sid.Equals(users):
			sawUsers = true
			if mask&writeBits != 0 {
				t.Errorf("Authenticated Users may only read; mask 0x%x grants a write, delete or ACL right", mask)
			}
			if mask&(windows.GENERIC_READ|windows.FILE_READ_DATA) == 0 {
				t.Errorf("Authenticated Users must read the file (the tray needs it); mask 0x%x", mask)
			}
		case sid.Equals(system):
			sawSystem = true
			if mask&(windows.GENERIC_ALL|windows.FILE_WRITE_DATA) == 0 {
				t.Errorf("SYSTEM must write the file; mask 0x%x", mask)
			}
		case sid.Equals(admins):
			sawAdmins = true
			if mask&(windows.GENERIC_ALL|windows.FILE_WRITE_DATA) == 0 {
				t.Errorf("Administrators must write the file; mask 0x%x", mask)
			}
		default:
			t.Errorf("unexpected ACE %d for %s (mask 0x%x)", i, sid.String(), mask)
		}
	}
	if !sawUsers || !sawSystem || !sawAdmins {
		t.Fatalf("expected ACEs for Authenticated Users, SYSTEM and Administrators; got users=%v system=%v admins=%v",
			sawUsers, sawSystem, sawAdmins)
	}
	_ = os.Remove(path)
}
