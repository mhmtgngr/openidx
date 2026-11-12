package tray

import (
	"fmt"

	"github.com/openidx/openidx/agent/internal/ipc"

	"github.com/openidx/openidx/agent/internal/updater"
)

// Version is the running build's version, set by main before Run. The
// About entry and the update check show and compare it.
var Version = "dev"

// ShouldRun is shouldStart for main: whether a tray launched with
// --autostart should run for this user.
func ShouldRun(launchedForAutostart bool) bool {
	return shouldStart(launchedForAutostart, AutostartDisabled())
}

// shouldStart decides whether a tray launched for autostart runs. The MSI's
// Run key starts the tray with --autostart at every sign-in; a person who
// turned "Start when I sign in" off keeps the Run key (it is machine-wide
// and theirs to keep for other users) and the tray simply exits. A tray
// started by hand, from the Start menu, always runs.
func shouldStart(launchedForAutostart, userDisabledAutostart bool) bool {
	return !launchedForAutostart || !userDisabledAutostart
}

// updateMessage is what Check for updates tells the person: the manifest's
// verdict against the running version, or why there is none.
func updateMessage(current string, manifestURL string, m *updater.Manifest, err error) string {
	switch {
	case manifestURL == "":
		return "Automatic updates are not configured on this device.\n\nYou are on OpenIDX " + current + "."
	case err != nil:
		return "The update server could not be checked.\n\n" + err.Error()
	case m == nil:
		return "The update server answered with no manifest."
	case updater.Newer(current, m.Version):
		return fmt.Sprintf("OpenIDX %s is available; you are on %s.\n\n"+
			"The OpenIDX service installs updates on its own, within six hours.", m.Version, current)
	}
	return "OpenIDX " + current + " is up to date."
}

// aboutText is the About box: build, update channel and the last update
// check's outcome, server and device (B8.11).
func aboutText(version, server, agentID, deviceID, configDir string, st *ipc.Status) string {
	if server == "" {
		server = "(not enrolled)"
	}
	msg := "OpenIDX agent " + version
	if st != nil {
		ch := st.UpdateChannel
		if ch == "" {
			ch = "stable"
		}
		msg += "\nUpdate channel: " + ch
		switch {
		case st.UpdatePaused:
			msg += " (updates paused by your organization)"
		case st.UpdateState == "failed":
			msg += "\nLast update: failed" + versionSuffix(st.UpdateVersion)
		case st.UpdateState == "applying":
			msg += "\nLast update: installing" + versionSuffix(st.UpdateVersion)
		case st.UpdateState == "ok":
			msg += "\nLast update check: up to date"
		}
	}
	msg += "\n\nServer: " + server
	if agentID != "" {
		msg += "\nAgent ID: " + agentID
	}
	if deviceID != "" {
		msg += "\nDevice ID: " + deviceID
	}
	if st != nil && st.Unclaimed {
		msg += "\nOwner: nobody yet. Sign in to claim this device."
	}
	return msg + "\nConfiguration: " + configDir
}

func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return " (" + v + ")"
}

// claimPrompt is what the tray shows for an unclaimed device, "" when it is
// not one (B8.11).
func claimPrompt(signedIn bool, st *ipc.Status) string {
	if st == nil || !st.Unclaimed || st.Revoked || !st.Enrolled {
		return ""
	}
	if signedIn {
		return "Claim this device"
	}
	return "Sign in to claim this device"
}
