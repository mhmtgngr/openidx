package tray

import (
	"strings"

	"github.com/openidx/openidx/agent/internal/ipc"
)

// The device's credential is refused (the service's AuthInvalid). The tray
// is the only place the person at the device hears about it: the service
// stops reporting and the console shows the device as offline. Before this,
// the menu kept saying "device: enrolled" while the server refused every
// report, for as long as nobody looked at the fleet.

// addDevicePath is the console page that makes an enrolment code for the
// signed-in person and hands it to this agent ("Open in app"). Enrolling
// from there also makes the device that person's, which a token enrolment
// does not.
const addDevicePath = "/add-device"

// reEnrollMessage is what the tray says when the device's credential is
// refused, once when it happens and again when the menu item is clicked
// without a server to open.
const reEnrollMessage = "The OpenIDX server no longer accepts this device's credential, " +
	"so it is not reporting its security checks and has no device trust.\n\n" +
	"Nothing was revoked. To fix it, enroll the device again: choose " +
	"\"Enroll this device again\" in the OpenIDX menu, sign in, and click " +
	"\"Open in app\" on the page that opens."

// addDeviceURL is the Add a device page on server, or "" when there is no
// server to open it on.
func addDeviceURL(server string) string {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		return ""
	}
	return server + addDevicePath
}

// needsReEnrollment reports whether the device should be enrolled again: the
// service says its credential is refused, and it is not revoked (a revoked
// device is the administrator's to take back, not the person's to re-enroll).
func needsReEnrollment(st *ipc.Status) bool {
	return st != nil && st.AuthInvalid && !st.Revoked
}

// becameAuthInvalid reports the transition into needsReEnrollment, so the
// person is told once rather than on every status tick.
func becameAuthInvalid(prev, cur *ipc.Status) bool {
	return needsReEnrollment(cur) && !needsReEnrollment(prev)
}
