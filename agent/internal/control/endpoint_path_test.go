package control

import (
	"path/filepath"
	"testing"
)

// TestEndpointPathFor: the file goes to the user's own LOCALAPPDATA whenever
// there is one, and to the machine-wide ProgramData only when there is not.
// Choosing ProgramData while LOCALAPPDATA is set is the case this guards: that
// was the old order, and it put the bearer in a directory every account shares.
func TestEndpointPathFor(t *testing.T) {
	local := filepath.Join("users", "alice", "AppData", "Local")
	shared := "ProgramData"
	tmp := "Temp"

	for _, tc := range []struct {
		name                string
		local, shared, temp string
		want                string
	}{
		{"LOCALAPPDATA set", local, shared, tmp,
			filepath.Join(local, "OpenIDX", "agent", "control-endpoint.json")},
		{"LOCALAPPDATA unset", "", shared, tmp,
			filepath.Join(shared, "OpenIDX", "agent", "control-endpoint.json")},
		{"neither set", "", "", tmp,
			filepath.Join(tmp, "OpenIDX", "agent", "control-endpoint.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := endpointPathFor(tc.local, tc.shared, tc.temp); got != tc.want {
				t.Errorf("endpointPathFor(%q, %q, %q) = %q, want %q",
					tc.local, tc.shared, tc.temp, got, tc.want)
			}
		})
	}
}
