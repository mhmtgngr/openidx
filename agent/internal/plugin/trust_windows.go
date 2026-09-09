//go:build windows

package plugin

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkTrustedPath reads the path's DACL and refuses it when a principal
// outside the trusted set holds a right that would let it replace what this
// process is about to execute.
//
// THIS FILE USED TO REFUSE EVERYTHING. The Unix half of the check is the file's
// mode bits, and Windows discards them — the Go runtime maps 0755 to "not
// read-only" and nothing else — so the same code here would have reported every
// path as trusted while checking nothing, in the one place where the process
// asking is the service, running as SYSTEM. Refusing was the honest answer while
// the real check did not exist. It exists now, and this is it.
//
// WHO IS TRUSTED, and why that list and not a shorter one:
//
//   - SYSTEM and BUILTIN\Administrators, because an account that already holds
//     those can replace the agent itself; a plugin is not the weak link there.
//   - NT SERVICE\TrustedInstaller, because it holds full control over
//     %ProgramFiles% on every Windows install. Leaving it out would refuse the
//     ordinary installation directory, and a check that refuses the normal
//     layout gets switched off.
//   - The account this process is running as. Same reasoning trust_other.go
//     gives for not comparing ownership against the uid: a file only this
//     identity can write is not an escalation, it is the identity that is
//     already running the code. In the deployment that matters — the Windows
//     service — this is SYSTEM, so the rule collapses to the strict one.
//
// WHAT COUNTS AS A DANGEROUS RIGHT: writing the bytes, appending to them,
// deleting the file, deleting a child of the directory, or taking control of
// the ACL or the ownership (from which every other right follows). Read and
// execute are not the question here; who can CHANGE what gets executed is.
//
// The owner is checked as well as the ACEs. An object's owner can rewrite its
// DACL whatever the DACL currently says, so an ACL that grants a non-privileged
// owner nothing is not a control — it is one API call away from granting them
// everything.
func checkTrustedPath(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the security descriptor of %s: %w "+
			"(this process executes what it finds there, so a path whose permissions "+
			"cannot be read is not one to execute from)", path, err)
	}

	trusted, err := trustedPrincipals()
	if err != nil {
		return fmt.Errorf("cannot determine which accounts are trusted to write %s: %w", path, err)
	}

	if owner, _, oerr := sd.Owner(); oerr != nil {
		return fmt.Errorf("cannot read the owner of %s: %w", path, oerr)
	} else if owner != nil && !isTrusted(owner, trusted) {
		return fmt.Errorf("%s is owned by %s: an owner can rewrite the permissions of what it "+
			"owns whatever they currently say, and this process executes what it finds there. "+
			"Give ownership to Administrators or SYSTEM (takeown /f %s /a)",
			path, nameOf(owner), path)
	}

	dacl, _, derr := sd.DACL()
	if derr != nil {
		return fmt.Errorf("cannot read the permissions of %s: %w", path, derr)
	}
	if dacl == nil {
		// A NULL DACL is not an empty one: it grants everyone full control.
		return fmt.Errorf("%s has a NULL DACL, which grants full control to everyone, and this "+
			"process executes what it finds there", path)
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("cannot read permission entry %d of %s: %w", i, path, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // a template for children; it does not apply to this object
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, aceTypeAudit, aceTypeAlarm:
			continue // a deny only narrows, and auditing grants nothing
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			// handled below
		default:
			// A callback or object ACE can grant access under a condition this
			// code cannot evaluate. Saying "safe" about an entry that was not
			// understood is the failure this whole file exists to avoid.
			return fmt.Errorf("%s carries a permission entry of type %d that this check cannot "+
				"evaluate, so it cannot report the path as safe to execute from",
				path, ace.Header.AceType)
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if granted := uint32(ace.Mask) & dangerousRights; granted != 0 && !isTrusted(sid, trusted) {
			return fmt.Errorf("%s grants %s to %s, and this process executes what it finds there. "+
				"Remove it (icacls %s /remove:g \"%s\")",
				path, describeRights(granted), nameOf(sid), path, nameOf(sid))
		}
	}
	return nil
}

// ACE types x/sys/windows does not name. Audit and alarm entries record access,
// they never grant it.
const (
	aceTypeAudit = 2
	aceTypeAlarm = 3
)

// fileDeleteChild is FILE_DELETE_CHILD, which x/sys/windows does not export. On
// a directory it permits deleting an entry regardless of that entry's own
// permissions — which is the whole attack on a plugin directory: you do not
// need to write the plugin if you can delete it and put your own there.
const fileDeleteChild = 0x40

// dangerousRights are the rights that let their holder change what gets
// executed. GENERIC_WRITE and GENERIC_ALL are included because an ACE may carry
// generic bits unmapped, and reading one as "no specific write right" would be
// a pass that was never earned.
const dangerousRights = windows.FILE_WRITE_DATA |
	windows.FILE_APPEND_DATA |
	fileDeleteChild |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// trustedInstallerSID is NT SERVICE\TrustedInstaller, which is a fixed,
// machine-independent SID rather than a well-known type x/sys can construct.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// trustedPrincipals returns the accounts allowed to hold write rights over a
// path this process will execute from. See the header for why each is here.
func trustedPrincipals() ([]*windows.SID, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("SYSTEM SID: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("Administrators SID: %w", err)
	}
	out := []*windows.SID{system, admins}

	// TrustedInstaller and the running account are both best-effort: a machine
	// that cannot resolve either is not a reason to refuse every path, it just
	// means those two are not in the trusted set on this machine.
	if ti, err := windows.StringToSid(trustedInstallerSID); err == nil {
		out = append(out, ti)
	}
	if self, err := currentProcessSID(); err == nil {
		out = append(out, self)
	}
	return out, nil
}

// currentProcessSID is the account this process runs as — SYSTEM for the
// service, the operator for `openidx-agent serve` at a console.
func currentProcessSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}

func isTrusted(sid *windows.SID, trusted []*windows.SID) bool {
	for _, t := range trusted {
		if sid.Equals(t) {
			return true
		}
	}
	return false
}

// nameOf renders a SID the way an operator will see it in icacls output,
// falling back to the SID itself for an account this machine cannot resolve
// (a deleted user, or one from a domain that is not reachable).
func nameOf(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + "\\" + account
}

// describeRights names what was granted, so the message says what is wrong
// rather than leaving the reader to decode a hexadecimal mask.
func describeRights(mask uint32) string {
	var names []string
	for _, r := range []struct {
		bit  uint32
		name string
	}{
		{windows.GENERIC_ALL, "full control"},
		{windows.GENERIC_WRITE, "generic write"},
		{windows.FILE_WRITE_DATA, "write"},
		{windows.FILE_APPEND_DATA, "append"},
		{fileDeleteChild, "delete-child"},
		{windows.DELETE, "delete"},
		{windows.WRITE_DAC, "change-permissions"},
		{windows.WRITE_OWNER, "take-ownership"},
	} {
		if mask&r.bit != 0 {
			names = append(names, r.name)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("mask %#x", mask)
	}
	return strings.Join(names, ", ")
}
