//go:build windows

package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/openidx/openidx/agent/internal/secretfile"
)

type endpointInfo struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

// endpointPath returns %LOCALAPPDATA%\OpenIDX\agent\control-endpoint.json,
// falling back to %ProgramData% when LOCALAPPDATA is unset; endpointPathFor
// gives the reasons.
func endpointPath() string {
	return endpointPathFor(os.Getenv("LOCALAPPDATA"), os.Getenv("ProgramData"), os.TempDir())
}

// newListener binds 127.0.0.1:0 and mints a random bearer token, writing the
// chosen address + token to an owner-only endpoint file the GUI reads. Windows
// lacks filesystem-permissioned UDS in this toolchain, so the token guards the
// loopback socket.
func newListener() (ln net.Listener, addr, token string, err error) {
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", "", fmt.Errorf("loopback listen: %w", err)
	}
	addr = ln.Addr().String()

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		_ = ln.Close()
		return nil, "", "", fmt.Errorf("generating control token: %w", err)
	}
	token = hex.EncodeToString(buf)

	// This file hands whoever reads it a bearer that fully drives the engine —
	// sign-in, enrolment, PAM launch, Ziti dial. It was written 0600, which
	// Windows ignores, so it inherited %ProgramData%'s ACL and every local
	// account could read it. It was then sealed with per-user DPAPI, which the
	// Flutter desktop shell cannot open, so the GUI never found the engine. It
	// is now plain JSON in a file only SYSTEM, Administrators and this user can
	// open; secretfile.WritePrivatePlain explains why that is the right
	// protection for a bearer that dies with this process.
	path := endpointPath()
	data, _ := json.Marshal(endpointInfo{Addr: addr, Token: token})
	if err := secretfile.WritePrivatePlain(path, data); err != nil {
		_ = ln.Close()
		return nil, "", "", fmt.Errorf("writing endpoint file: %w", err)
	}
	return ln, addr, token, nil
}

// cleanupListener removes the endpoint file after shutdown. (addr is host:port
// here, not a filesystem path, so it is not removed.)
func cleanupListener(addr string) {
	_ = os.Remove(endpointPath())
}
