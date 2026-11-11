//go:build windows

package winservice

import (
	"golang.org/x/sys/windows"
)

// consoleLogonUser is DOMAIN\user of the person signed in at the console
// session, or "" when nobody is. The service reads it itself rather than
// taking it from the tray: the tray pipe is read-only for users on purpose
// (ipc.pipeSDDL), and a name a user process hands the service is a name that
// user chose. The server matches it only under claim_mode logged_on_user, and
// only against directory- or federation-sourced users.
func consoleLogonUser() string {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF || session == 0 {
		return ""
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil || account == "" {
		return ""
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
