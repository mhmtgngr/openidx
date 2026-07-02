package access

import (
	"encoding/json"
	"strings"
	"testing"
)

// The session-history DTO must expose only a transcript/recording availability
// boolean — never the on-disk recording_path or transcript_path.
func TestGuacSessionRowHidesFilePaths(t *testing.T) {
	b, _ := json.Marshal(GuacSessionRow{})
	lower := strings.ToLower(string(b))
	for _, forbidden := range []string{"recording_path", "transcript_path"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("GuacSessionRow exposes a file-path field %q: %s", forbidden, b)
		}
	}
}

func TestBuildInjectedParams(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		secretType    string
		injectUser    string
		cred          []byte
		record        bool
		recordingPath string
		recordingName string
		wantKeys      map[string]string
		absentKeys    []string
	}{
		{
			name:       "password secret with username",
			secretType: "password",
			injectUser: "admin",
			cred:       []byte("s3cr3t"),
			record:     false,
			wantKeys:   map[string]string{"username": "admin", "password": "s3cr3t"},
			absentKeys: []string{"private-key", "recording-path", "recording-name", "recording-include-keys"},
		},
		{
			name:       "ssh_key secret uses private-key not password",
			secretType: "ssh_key",
			injectUser: "deploy",
			cred:       []byte("-----BEGIN RSA PRIVATE KEY-----"),
			record:     false,
			wantKeys:   map[string]string{"username": "deploy", "private-key": "-----BEGIN RSA PRIVATE KEY-----"},
			absentKeys: []string{"password", "recording-path", "recording-name", "recording-include-keys"},
		},
		{
			name:       "empty cred produces no credential keys",
			secretType: "password",
			injectUser: "user1",
			cred:       []byte{},
			record:     false,
			wantKeys:   map[string]string{},
			absentKeys: []string{"username", "password", "private-key"},
		},
		{
			name:       "nil cred produces no credential keys",
			secretType: "password",
			injectUser: "user1",
			cred:       nil,
			record:     false,
			wantKeys:   map[string]string{},
			absentKeys: []string{"username", "password", "private-key"},
		},
		{
			name:          "record=true sets all recording keys",
			secretType:    "password",
			injectUser:    "",
			cred:          []byte{},
			record:        true,
			recordingPath: "/var/recordings",
			recordingName: "conn-123-1234567890",
			wantKeys: map[string]string{
				"recording-path":         "/var/recordings",
				"recording-name":         "conn-123-1234567890",
				"recording-include-keys": "true",
			},
			absentKeys: []string{"username", "password", "private-key"},
		},
		{
			name:          "record=false omits recording keys",
			secretType:    "password",
			injectUser:    "alice",
			cred:          []byte("pw"),
			record:        false,
			recordingPath: "/var/recordings",
			recordingName: "conn-456-9999",
			wantKeys:      map[string]string{"username": "alice", "password": "pw"},
			absentKeys:    []string{"recording-path", "recording-name", "recording-include-keys"},
		},
		{
			name:       "empty injectUsername omits username key",
			secretType: "password",
			injectUser: "",
			cred:       []byte("pw"),
			record:     false,
			wantKeys:   map[string]string{"password": "pw"},
			absentKeys: []string{"username", "private-key", "recording-path"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildInjectedParams(tc.secretType, tc.injectUser, tc.cred, tc.record, tc.recordingPath, tc.recordingName)

			for k, want := range tc.wantKeys {
				if v, ok := got[k]; !ok {
					t.Errorf("key %q missing from result", k)
				} else if v != want {
					t.Errorf("key %q: got %q, want %q", k, v, want)
				}
			}

			for _, k := range tc.absentKeys {
				if _, ok := got[k]; ok {
					t.Errorf("key %q should be absent but is present (value=%q)", k, got[k])
				}
			}
		})
	}
}
