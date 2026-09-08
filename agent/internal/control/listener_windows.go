//go:build windows

package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/openidx/openidx/agent/internal/secretfile"
)

// endpointFileName holds the chosen loopback port + bearer token so a local GUI
// (same user) can discover how to reach the control server. Written 0600.
const endpointFileName = "control-endpoint.json"

type endpointInfo struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

// endpointPath returns %ProgramData%\OpenIDX\agent\control-endpoint.json (or a
// LocalAppData fallback), matching where the agent stores its config.
func endpointPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = os.Getenv("LOCALAPPDATA")
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "OpenIDX", "agent", endpointFileName)
}

// newListener binds 127.0.0.1:0 and mints a random bearer token, writing the
// chosen address + token to a 0600 endpoint file the GUI reads. Windows lacks
// filesystem-permissioned UDS in this toolchain, so the token guards the
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
	// account could read it. secretfile applies DPAPI (per-user) plus an
	// explicit file ACL; see agent/internal/secretfile.
	path := endpointPath()
	data, _ := json.Marshal(endpointInfo{Addr: addr, Token: token})
	if err := secretfile.Write(path, data); err != nil {
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
