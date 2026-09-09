//go:build windows

package secretfile

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect encrypts data with DPAPI in the CALLING USER's scope
// (CryptProtectData with no CRYPTPROTECT_LOCAL_MACHINE flag), so the blob is
// undecryptable by another account on the same machine even if it is copied
// out. The two files this package guards are written and read in the same
// interactive session — the tray, the CLI and `openidx-agent serve` — so a
// per-user scope is the tightest one that still works.
//
// The entropy argument is deliberately nil. A second secret would have to live
// beside the file to be usable, which is the shape of a lock next to its key.
func protect(data []byte) (blob []byte, protected bool, err error) {
	in := windows.DataBlob{Size: uint32(len(data))}
	if len(data) > 0 {
		in.Data = &data[0]
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, false, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) }()

	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), true, nil
}

// unprotect reverses protect. A blob written by a different user, or on a
// different machine, fails here — which is the point.
func unprotect(blob []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(blob))}
	if len(blob) > 0 {
		in.Data = &blob[0]
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData (the secret belongs to another user or machine): %w", err)
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) }()

	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// harden replaces the file's inherited permissions with an explicit list.
//
// This is the half that stops the file being READ, and it has to be set on the
// file rather than trusted from the directory: %ProgramData%\OpenIDX\agent
// inherits %ProgramData%, where BUILTIN\Users has read. PROTECTED_DACL means
// "stop inheriting", so the three entries below are the whole story:
//
//	NT AUTHORITY\SYSTEM        the service, and recovery
//	BUILTIN\Administrators     an admin can already take ownership, so denying
//	                           them buys nothing and breaks support
//	the writing user           the only account that can decrypt the DPAPI blob
//	                           anyway
func harden(path string) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("SYSTEM sid: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("Administrators sid: %w", err)
	}
	user, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("current user sid: %w", err)
	}

	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, sid := range []*windows.SID{system, admins, user} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}

	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("building DACL: %w", err)
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

// hardenShared deliberately does nothing on Windows.
//
// harden's ACL names the account that WROTE the file, which is exactly wrong
// for one more than one identity has to read: agent.json is written by whichever
// of the SYSTEM service and the user's tray enrolled first, and a PROTECTED_DACL
// naming that writer locks the other one out. Leaving the inherited ACL is what
// this file has always had, and the directory-ACL decision it still needs is
// recorded in docs/CLIENT-ACCESS-DESIGN.md §4 rather than half-made here.
func hardenShared(path string) error { return nil }

// currentUserSID returns the SID of the account this process runs as.
func currentUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tokenUser.User.Sid, nil
}
