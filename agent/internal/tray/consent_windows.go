//go:build windows

package tray

import (
	"golang.org/x/sys/windows"

	"github.com/openidx/openidx/agent/internal/agent"
)

// idYes is MessageBox's return value for the Yes button (x/sys/windows has
// the MB_ flags but not the ID return codes).
const idYes = 6

// askConsent puts the attended-support question to the person at the device
// and blocks until they answer. It is the prompt behind consentGate, so it
// runs on the gate's goroutine, never on the agent's poll.
func askConsent(rs *agent.RemoteSupportBlock) bool {
	mode := "see your screen"
	if rs != nil && rs.Mode == "control" {
		mode = "see your screen and control this device"
	}
	msg := "An OpenIDX administrator is asking for remote support on this device.\n\n" +
		"If you allow it, the administrator will " + mode + " until the session ends. " +
		"The OpenIDX icon shows a banner for as long as it lasts.\n\n" +
		"Allow remote support?"
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return false
	}
	caption, err := windows.UTF16PtrFromString("OpenIDX remote support")
	if err != nil {
		return false
	}
	ret, err := windows.MessageBox(0, text, caption,
		windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_DEFBUTTON2|windows.MB_SETFOREGROUND|windows.MB_TOPMOST)
	if err != nil {
		return false
	}
	return ret == idYes
}
