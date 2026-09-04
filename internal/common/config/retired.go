package config

import (
	"fmt"
	"os"
	"sort"
)

// retiredSettings names environment variables this codebase once accepted and
// no longer reads, with what became of each.
//
// A setting that is silently ignored is worse than one that was never offered:
// the operator who set it believes something changed. Two of the three below
// are why this table exists. ENABLE_MFA and ENABLE_AUDIT_LOGGING had struct
// fields, defaults, and a line each in a shipped config file
// (configs/audit-service.yaml) — and no line of this codebase ever read
// either. `ENABLE_MFA=false` got you MFA; `ENABLE_AUDIT_LOGGING=false` got you
// audit logging. Deleting the fields without saying so would have kept the
// operator's belief intact and only removed the evidence.
//
// The reason string is what the operator reads, so it says what to do instead
// where there is something to do.
var retiredSettings = map[string]string{
	"ENABLE_MFA": "no build ever read it. MFA is per user, from the factors that user has enrolled; " +
		"there is no global off switch, and setting this to false never produced one",
	"ENABLE_AUDIT_LOGGING": "no build ever read it. Audit logging is not optional in OpenIDX, " +
		"and setting this to false never turned it off",
	"OAUTH_LOGIN_UI": "the server-rendered login page it could select was deleted; the SPA login is the only one. " +
		"Set OAUTH_LOGIN_URL to the console's /login when the console is not served from the issuer's origin",
}

// RetiredSettingsInUse returns one line per retired setting present in the
// process environment, sorted for a stable log. Nil when none are set, which is
// the case for every install that never used them.
//
// Services log this at startup in EVERY environment, not just production:
// development is exactly where an operator tries a switch and needs to be told
// it does nothing.
func RetiredSettingsInUse() []string {
	var out []string
	for name, reason := range retiredSettings {
		if _, ok := os.LookupEnv(name); ok {
			out = append(out, fmt.Sprintf("%s is set but no longer read: %s", name, reason))
		}
	}
	sort.Strings(out)
	return out
}

// RetiredSettingNames returns the retired names, sorted. Used by the test that
// keeps a retired setting from quietly coming back as a binding or a default.
func RetiredSettingNames() []string {
	names := make([]string, 0, len(retiredSettings))
	for name := range retiredSettings {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
