//go:build windows

package secretfile

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestWritePrivatePlainIsBornWithTheOwnerOnlyDACL: control-endpoint.json is
// plain JSON, so its DACL is the whole of its protection. The path starts out
// holding a file created under the directory's inherited ACL, as an older
// engine's file was, and WritePrivatePlain must replace it with one whose DACL
// is protected from inheritance and names only SYSTEM, Administrators and the
// writer. A reused file would keep the inherited entries.
func TestWritePrivatePlainIsBornWithTheOwnerOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-endpoint.json")
	if err := os.WriteFile(path, []byte("inherited"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"addr":"127.0.0.1:50000","token":"drives-the-engine"}`)
	if err := WritePrivatePlain(path, data); err != nil {
		t.Fatalf("WritePrivatePlain: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if IsProtected(raw) || string(raw) != string(data) {
		t.Fatalf("stored %q, want the plain payload; the GUI cannot open a sealed file", raw)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	if ctrl, _, err := sd.Control(); err != nil {
		t.Fatalf("Control: %v", err)
	} else if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the DACL is not protected, so the directory's entries apply to the file")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	self, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}

	var sawSystem, sawAdmins, sawSelf bool
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			t.Errorf("ACE %d is inherited; the file's own list must be the whole list", i)
		}
		// Checked one by one rather than as a switch: a job that runs as SYSTEM
		// is SYSTEM and the writer at once.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		known := false
		for _, who := range []struct {
			sid *windows.SID
			saw *bool
		}{{system, &sawSystem}, {admins, &sawAdmins}, {self, &sawSelf}} {
			if sid.Equals(who.sid) {
				*who.saw, known = true, true
			}
		}
		if !known {
			t.Errorf("ACE %d grants %s, which is none of SYSTEM, Administrators or the writer", i, sid.String())
		}
	}
	if !sawSystem || !sawAdmins || !sawSelf {
		t.Errorf("want ACEs for SYSTEM, Administrators and the writer; got system=%v admins=%v writer=%v",
			sawSystem, sawAdmins, sawSelf)
	}
}
