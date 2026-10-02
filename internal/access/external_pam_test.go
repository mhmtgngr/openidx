package access

import (
	"testing"

	"github.com/openidx/openidx/internal/externalid"
)

// I7 of the third-party access framework at the broker parameters: an external
// user's session runs with clipboard, drive, file transfer and printing off
// and a recording nothing in the entry's settings can thin out, whatever those
// settings say; an internal user's session runs with the settings as stored.
func TestAnExternalSessionsControlsCannotBeOpenedBySettings(t *testing.T) {
	settings := map[string]interface{}{
		"disable-copy": "false", "disable-paste": "false",
		"enable-drive": "true", "drive-path": "/srv/share",
		"disable-download": "false", "disable-upload": "false",
		"enable-sftp": "true", "sftp-disable-download": "false", "sftp-disable-upload": "false",
		"enable-printing":          "true",
		"recording-exclude-output": "true", "recording-exclude-mouse": "true", "recording-exclude-touch": "true",
		"color-scheme": "gray-black",
	}

	internal := buildPamGuacParams("password", "deploy", "", []byte("pw"), settings, false, "", "")
	for k, v := range settings {
		if internal[k] != v.(string) {
			t.Errorf("an internal session's %s is %q, want the entry's %q", k, internal[k], v)
		}
	}

	external := buildPamGuacParams("password", "deploy", "", []byte("pw"), settings, true, "/recordings", "pam-e-1")
	hardenExternalGuacParams(external)
	for k, want := range map[string]string{
		"disable-copy": "true", "disable-paste": "true",
		"enable-drive":     "false",
		"disable-download": "true", "disable-upload": "true",
		"enable-sftp": "false", "sftp-disable-download": "true", "sftp-disable-upload": "true",
		"enable-printing": "false",
		"recording-path":  "/recordings", "recording-name": "pam-e-1", "recording-include-keys": "true",
		"color-scheme": "gray-black",
		"username":     "deploy", "password": "pw",
	} {
		if external[k] != want {
			t.Errorf("an external session's %s is %q, want %q", k, external[k], want)
		}
	}
	for _, k := range []string{"recording-exclude-output", "recording-exclude-mouse", "recording-exclude-touch"} {
		if v, ok := external[k]; ok {
			t.Errorf("an external session kept %s=%q, which thins out its recording", k, v)
		}
	}

	// What the launch answers names the same controls.
	policy := externalSessionPolicy()
	for k, want := range map[string]interface{}{
		"approval": true, "recorded": true, "overlay": true,
		"clipboard": false, "drive": false, "file_transfer": false, "printing": false,
		"max_minutes": int(externalid.MaxPamSession.Minutes()),
	} {
		if policy[k] != want {
			t.Errorf("session_policy %s is %v, want %v", k, policy[k], want)
		}
	}
}

// pinExternalPamPolicy turns an external caller's launch into an approved,
// recorded one whatever the entry says, and leaves anyone else's alone.
func TestAnExternalLaunchIsApprovedAndRecordedWhateverTheEntrySays(t *testing.T) {
	entry := pamLaunchEntry{RequireApproval: false, RecordSession: false}
	pinExternalPamPolicy(&entry, pamCaller{UserID: "u"})
	if entry.External || entry.RequireApproval || entry.RecordSession {
		t.Errorf("an internal caller's launch was changed: %+v", entry)
	}
	pinExternalPamPolicy(&entry, pamCaller{UserID: "u", External: true})
	if !entry.External || !entry.RequireApproval || !entry.RecordSession {
		t.Errorf("an external caller's launch is %+v, want external, approval and recording", entry)
	}
}
