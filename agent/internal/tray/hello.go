package tray

import "strings"

// notEnrolledMessage is what the tray says when an action needs a server
// and the device has none yet: nothing to sign in to, nowhere to open.
const notEnrolledMessage = "This device is not enrolled yet, so there is nothing to sign in to.\n\n" +
	"Open the enrollment link from the OpenIDX console on this computer, or run\n" +
	"openidx-agent enroll --code <code> --server <url> from an administrator prompt."

// securityKeysPath is the console page where a signed-in person registers
// a passkey (Windows Hello, or a FIDO2 security key) for their own account.
// Any signed-in user can open it by URL; the console's navigation only lists
// it for administrators. The Flutter desktop client opens the same page.
const securityKeysPath = "/security-keys"

// securityKeysURL is the Security Keys page on server, or "" when there is
// no server to open it on (the device is not enrolled).
func securityKeysURL(server string) string {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		return ""
	}
	return server + securityKeysPath
}
