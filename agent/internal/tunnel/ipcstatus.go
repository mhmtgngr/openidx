package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// IPCDiscriminator is the -P value the supervisor runs the tunneler with. The
// tunneler suffixes its command socket with it (ziti-edge-tunnel.sock.openidx),
// so ours is never the instance a person's own Ziti Desktop Edge answers for,
// and `tunnel_status -P openidx` asks exactly ours.
const IPCDiscriminator = "openidx"

// ipcResponse is the tunneler's IPC envelope ({"Success","Code","Data"}) with
// the parts of its tunnel_status model (programs/ziti-edge-tunnel/include/
// model/dtos.h, TUNNEL_STATUS) this package reads.
type ipcResponse struct {
	Success bool   `json:"Success"`
	Code    int    `json:"Code"`
	Error   string `json:"Error"`
	Data    *struct {
		Active         bool `json:"Active"`
		ServiceVersion *struct {
			Version string `json:"Version"`
		} `json:"ServiceVersion"`
		Identities []struct {
			Name         string `json:"Name"`
			Identifier   string `json:"Identifier"`
			Active       bool   `json:"Active"`
			Loaded       bool   `json:"Loaded"`
			NeedsExtAuth bool   `json:"NeedsExtAuth"`
			MfaNeeded    bool   `json:"MfaNeeded"`
			Services     []struct {
				Name        string `json:"Name"`
				Permissions *struct {
					Dial bool `json:"Dial"`
				} `json:"Permissions"`
			} `json:"Services"`
		} `json:"Identities"`
	} `json:"Data"`
}

// ipcReading is what one tunnel_status answer says.
type ipcReading struct {
	State    State
	Version  string
	Services []string
	Detail   string
}

// queryIPC runs `<bin> tunnel_status -P <pipe>` and reads its answer.
func queryIPC(ctx context.Context, bin *heldBinary, pipe string, timeout time.Duration) (ipcReading, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := bin.command(ctx, "tunnel_status", "-P", pipe)
	hideWindow(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	reading, perr := parseIPCStatus(stdout.Bytes())
	if perr == nil {
		return reading, nil
	}
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return ipcReading{}, fmt.Errorf("tunnel_status: %s", msg)
	}
	return ipcReading{}, perr
}

// parseIPCStatus reads the tunnel_status CLI's output: the pretty-printed IPC
// response, possibly after a log line, so the JSON object is cut out from the
// first '{' to the last '}'.
func parseIPCStatus(out []byte) (ipcReading, error) {
	start, end := bytes.IndexByte(out, '{'), bytes.LastIndexByte(out, '}')
	if start < 0 || end < start {
		return ipcReading{}, errors.New("tunnel_status printed no JSON")
	}
	var resp ipcResponse
	if err := json.Unmarshal(out[start:end+1], &resp); err != nil {
		return ipcReading{}, fmt.Errorf("tunnel_status JSON: %w", err)
	}
	if !resp.Success || resp.Data == nil {
		msg := resp.Error
		if msg == "" {
			msg = fmt.Sprintf("code %d", resp.Code)
		}
		return ipcReading{}, fmt.Errorf("tunnel_status refused: %s", msg)
	}
	r := ipcReading{State: StateDegraded}
	if resp.Data.ServiceVersion != nil {
		r.Version = resp.Data.ServiceVersion.Version
	}
	seen := map[string]bool{}
	activeIDs := 0
	var problems []string
	for _, id := range resp.Data.Identities {
		name := id.Name
		if name == "" {
			name = id.Identifier
		}
		switch {
		case !id.Loaded:
			problems = append(problems, name+" is not loaded")
		case id.NeedsExtAuth || id.MfaNeeded:
			problems = append(problems, name+" is waiting for authentication")
		case !id.Active:
			problems = append(problems, name+" is disabled")
		default:
			activeIDs++
		}
		for _, svc := range id.Services {
			if svc.Name == "" || seen[svc.Name] {
				continue
			}
			if svc.Permissions != nil && !svc.Permissions.Dial {
				continue // a service this device hosts, not one it intercepts
			}
			seen[svc.Name] = true
			r.Services = append(r.Services, svc.Name)
		}
	}
	sort.Strings(r.Services)
	switch {
	case !resp.Data.Active:
		r.Detail = "the tunneler reports itself inactive"
	case len(resp.Data.Identities) == 0:
		r.Detail = "the tunneler has loaded no identity"
	case len(problems) > 0:
		r.Detail = "identity " + strings.Join(problems, "; ")
	case activeIDs > 0:
		r.State = StateConnected
	}
	return r, nil
}

// queryVersion runs `<bin> version`, which prints the tunneler's version.
func queryVersion(ctx context.Context, bin *heldBinary, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := bin.command(ctx, "version")
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			return v
		}
	}
	return ""
}
