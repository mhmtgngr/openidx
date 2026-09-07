package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// retiredSetting is one setting this codebase once accepted and no longer reads.
type retiredSetting struct {
	// ViperKey is the configuration key the setting was bound under, dotted as
	// viper spells it ("push_mfa.fcm_server_key"). It is what the tests use to
	// prove the struct field, the default and the shipped-config line are all
	// gone, and it is how the second spelling below is derived.
	ViperKey string
	// Reason is what the operator reads. It says what became of the setting and
	// what to do instead where there is something to do.
	Reason string
}

// retiredSettings names environment variables this codebase once accepted and
// no longer reads, with what became of each.
//
// A setting that is silently ignored is worse than one that was never offered:
// the operator who set it believes something changed. ENABLE_MFA and
// ENABLE_AUDIT_LOGGING are why this table exists. Both had struct fields,
// defaults, and a line each in the shipped config file — and no line of this
// codebase ever read either. `ENABLE_MFA=false` got you MFA;
// `ENABLE_AUDIT_LOGGING=false` got you audit logging. Deleting the fields
// without saying so would have kept the operator's belief intact and only
// removed the evidence.
//
// That shipped config file is gone too, for the same reason one level up: it was
// named configs/audit-service.yaml while Load looks only for config.yaml, so no
// process could ever open it, and its `${VAR:default}` lines implied an
// interpolation step nothing performs. The reference for what can be set is
// docs/docs/deployment/configuration.md, which tools/deadconfig gates.
//
// tools/deadconfig now finds this class by census rather than by somebody
// noticing, and this table is where its findings come to rest: the field, the
// default and the binding go, and the name stays here saying so.
var retiredSettings = map[string]retiredSetting{
	"ENABLE_MFA": {
		ViperKey: "enable_mfa",
		Reason: "no build ever read it. MFA is per user, from the factors that user has enrolled; " +
			"there is no global off switch, and setting this to false never produced one",
	},
	"ENABLE_AUDIT_LOGGING": {
		ViperKey: "enable_audit_logging",
		Reason: "no build ever read it. Audit logging is not optional in OpenIDX, " +
			"and setting this to false never turned it off",
	},
	"OAUTH_LOGIN_UI": {
		ViperKey: "oauth_login_ui",
		Reason: "the server-rendered login page it could select was deleted; the SPA login is the only one. " +
			"Set OAUTH_LOGIN_URL to the console's /login when the console is not served from the issuer's origin",
	},
	"FCM_SERVER_KEY": {
		ViperKey: "push_mfa.fcm_server_key",
		Reason: "the legacy FCM server key. Google decommissioned the legacy HTTP and XMPP APIs in 2024 and " +
			"no build ever sent it; push notifications go out over FCM HTTP v1. Set PUSH_MFA_FCM_CREDENTIALS_FILE " +
			"to a Firebase service-account JSON and PUSH_MFA_FCM_PROJECT_ID to the project it belongs to",
	},
	"JWT_SECRET": {
		ViperKey: "jwt_secret",
		Reason: "no build ever signed or verified anything with it. Every token OpenIDX mints or accepts is " +
			"RS256, signed with the rotatable key in oauth_signing_keys — encrypted at rest with ENCRYPTION_KEY — " +
			"and verified through JWKS; the shared middleware refuses any other algorithm by name. Rotating this " +
			"value rotated nothing: rotate the real key with POST /api/v1/admin/oauth/signing-keys/rotate",
	},
	"SMS_OTP_LENGTH": {
		ViperKey: "sms.otp_length",
		Reason: "OTP length is an installation setting, not a per-service one: it is stored in the database and " +
			"edited in the admin console under Settings → SMS, where the identity service picks it up without a " +
			"restart. This copy was read by nothing, so an install that set it here still issued six-digit codes",
	},
	"SMS_OTP_EXPIRY": {
		ViperKey: "sms.otp_expiry",
		Reason: "OTP lifetime is an installation setting, not a per-service one: it is stored in the database and " +
			"edited in the admin console under Settings → SMS. This copy was read by nothing, so an install that " +
			"set it here still issued codes valid for five minutes",
	},
	"SMS_MAX_ATTEMPTS": {
		ViperKey: "sms.max_attempts",
		Reason: "the verification-attempt ceiling is an installation setting, not a per-service one: it is stored " +
			"in the database and edited in the admin console under Settings → SMS. This copy was read by nothing, " +
			"so an install that set it here still allowed three attempts",
	},
}

// RetiredSettingsInUse returns one line per retired setting present in the
// process environment, sorted for a stable log. Nil when none are set, which is
// the case for every install that never used them.
//
// Both spellings are checked. Viper's AutomaticEnv with the OPENIDX prefix makes
// OPENIDX_PUSH_MFA_FCM_SERVER_KEY a second name for push_mfa.fcm_server_key, and
// the operator who followed the MFA guide set exactly that one — so the prefixed
// form is derived from the key rather than listed, and cannot fall out of step
// with it.
//
// Services log this at startup in EVERY environment, not just production:
// development is exactly where an operator tries a switch and needs to be told
// it does nothing.
func RetiredSettingsInUse() []string {
	var out []string
	for name, setting := range retiredSettings {
		for _, spelling := range settingSpellings(name, setting.ViperKey) {
			if _, ok := os.LookupEnv(spelling); ok {
				out = append(out, fmt.Sprintf("%s is set but no longer read: %s", spelling, setting.Reason))
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// settingSpellings returns the environment-variable names that reached a key:
// the one the shipped config and the docs named, and viper's own
// OPENIDX_<KEY> form.
func settingSpellings(name, viperKey string) []string {
	prefixed := "OPENIDX_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(viperKey))
	if prefixed == name {
		return []string{name}
	}
	return []string{name, prefixed}
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

// RetiredSettingKey returns the viper key a retired setting was bound under.
// Empty for a name that is not retired.
func RetiredSettingKey(name string) string { return retiredSettings[name].ViperKey }
