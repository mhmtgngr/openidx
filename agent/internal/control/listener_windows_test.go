//go:build windows

package control

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestTheEndpointFileIsPlainJSONInLocalAppData is what the Flutter desktop
// shell needs in order to find the engine: the file in the user's LOCALAPPDATA,
// readable with a plain JSON decode, naming the address and bearer the
// listener actually uses. It used to be a DPAPI blob in ProgramData, which the
// shell could never parse. The file's DACL must still be protected, because
// the JSON is no longer sealed.
func TestTheEndpointFileIsPlainJSONInLocalAppData(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)

	ln, addr, token, err := newListener()
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	defer ln.Close()

	path := filepath.Join(local, "OpenIDX", "agent", "control-endpoint.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the endpoint file is not in LOCALAPPDATA: %v", err)
	}
	if bytes.HasPrefix(raw, []byte("OPENIDX-SECRETFILE-")) {
		t.Fatalf("the endpoint file is sealed (%d bytes), which the GUI cannot read", len(raw))
	}
	var got endpointInfo
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the endpoint file is not plain JSON: %v", err)
	}
	if got.Addr != addr || got.Token != token {
		t.Errorf("the file names %s, want the listener's address %s and its token", got.Addr, addr)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	if ctrl, _, err := sd.Control(); err != nil {
		t.Fatalf("Control: %v", err)
	} else if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the endpoint file's DACL is not protected from inheritance")
	}

	cleanupListener(addr)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanupListener left the endpoint file behind: %v", err)
	}
}
