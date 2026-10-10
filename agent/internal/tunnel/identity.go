package tunnel

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openidx/openidx/agent/internal/secretfile"
)

// ErrNoIdentity is returned when the agent has no enrolled Ziti identity to
// hand the tunneler.
var ErrNoIdentity = errors.New("this device has no enrolled Ziti identity")

// identityPrefix is the prefix of every identity file the supervisor writes.
// The server names the device identity dev-<agent_id> (internal/access/
// device_identity.go), and the file carries the same name.
const identityPrefix = "dev-"

// IdentityFileName is the file the device identity is written to in the
// tunneler's identity directory.
func IdentityFileName(agentID string) string {
	return identityPrefix + agentID + ".json"
}

// Provisioner puts the agent's enrolled identity (Source, the
// ziti-identity.json the enrolment wrote) into Dir as dev-<AgentID>.json, the
// directory the tunneler is started with (run --identity-dir). The identity
// the OpenZiti Go SDK writes ({"ztAPI", "id": {"cert","key","ca"}} with "pem:"
// values) is the format the C SDK under ziti-edge-tunnel reads, so it is
// copied, not converted.
type Provisioner struct {
	Source, Dir, AgentID string

	// copied is the digest of the source last copied. The tunneler rewrites
	// its identity file itself (a new controller list, for one), so the copy
	// is compared with the SOURCE it came from, not with the file as the
	// tunneler left it: comparing with the file would see every such rewrite
	// as a new identity and restart the tunneler each time it made one.
	copied [sha256.Size]byte
	have   bool
}

// Provision makes Dir hold the current identity and nothing else of ours. The
// copy is born private (secretfile.WritePrivatePlain: owner-only DACL on
// Windows, 0600 elsewhere): it holds the device's private key. Any other
// dev-*.json in Dir is removed, so a device that was enrolled again does not
// keep the tunneler loading its old identity next to the new one. changed
// means a running tunneler must be restarted to pick the directory up.
func (p *Provisioner) Provision() (changed bool, err error) {
	if p.Source == "" || p.AgentID == "" {
		return false, ErrNoIdentity
	}
	data, err := os.ReadFile(p.Source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, ErrNoIdentity
		}
		return false, fmt.Errorf("reading device identity: %w", err)
	}
	if !json.Valid(data) {
		return false, fmt.Errorf("device identity %s is not JSON", p.Source)
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return false, fmt.Errorf("creating tunnel identity directory: %w", err)
	}
	dst := filepath.Join(p.Dir, IdentityFileName(p.AgentID))
	sum := sha256.Sum256(data)
	_, statErr := os.Stat(dst)
	if statErr != nil || !p.have || sum != p.copied {
		// Missing, never copied by this process, or a new source. On the
		// first pass an existing copy that already matches is left alone.
		if cur, rerr := os.ReadFile(dst); rerr != nil || !bytes.Equal(cur, data) {
			if err := secretfile.WritePrivatePlain(dst, data); err != nil {
				return false, fmt.Errorf("writing tunnel identity: %w", err)
			}
			changed = true
		}
		p.copied, p.have = sum, true
	}
	removed, err := removeStale(p.Dir, filepath.Base(dst))
	return changed || removed, err
}

// Forget removes every identity file the supervisor wrote into Dir. It is how
// the tunnel is turned off in external mode, where the agent does not own the
// process, and it keeps the private key's copy off a device whose tunnel is
// off.
func (p *Provisioner) Forget() (bool, error) {
	p.have = false
	return removeStale(p.Dir, "")
}

func removeStale(dir, keep string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	removed := false
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == keep || !strings.HasPrefix(n, identityPrefix) || !strings.HasSuffix(n, ".json") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("removing stale tunnel identity %s: %w", n, err)
		}
		removed = true
	}
	return removed, nil
}
