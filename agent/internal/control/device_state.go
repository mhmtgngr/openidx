package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/transport"
)

// What the device is allowed to do, told to the device.
//
// The design's first rule is that a device starts with the minimum and earns
// more by proving things, and that the user always sees which of those it has.
// The client could not: Status() reports what is on disk — enrolled, has a Ziti
// identity, signed in — and none of that distinguishes "enrolled and waiting
// for an administrator" from "enrolled and working", or either from "revoked".
// A device that is waiting looks, to its user, exactly like one that is broken.
//
// The server has always known. GET /agent/config branches on the agent's status
// to decide which posture checks to send, and answers 403 for a revoked one; it
// now also states the status and the device's IAM trust flag outright. This is
// the client half: one call, authenticated with the agent's own credential, and
// a flat payload the UI can render without inventing anything.

// deviceStatePayload is the JSON DeviceState returns. Flat and string/bool
// only, because it crosses the gomobile boundary.
type deviceStatePayload struct {
	// Enrolled is local truth: is there an agent identity on this device at all.
	Enrolled bool `json:"enrolled"`
	// State is the server's word: pending, active, suspended, revoked — or
	// "not_enrolled" when there is nothing to ask about, and "unknown" when the
	// server could not be reached.
	State string `json:"state"`
	// DeviceTrusted is the IAM device-trust flag the overlay's #device-trusted
	// attribute follows. False whenever State is not known to be active.
	DeviceTrusted bool `json:"device_trusted"`
	// ServerReachable separates "the server says you are pending" from "I could
	// not ask". The UI must not render an unreachable server as a refusal.
	ServerReachable bool `json:"server_reachable"`
	// Error carries why the ask failed, for the log and for a diagnostic line.
	Error     string `json:"error,omitempty"`
	CheckedAt int64  `json:"checked_at"`
}

// agentConfigState is the part of the /agent/config response this reads.
type agentConfigState struct {
	EnrollmentStatus string `json:"enrollment_status"`
	DeviceTrusted    bool   `json:"device_trusted"`
}

// DeviceState asks the server what this device is currently allowed to do and
// returns the answer as a JSON string.
//
// It never fails for an ordinary reason: not enrolled, offline and revoked are
// all states with a payload, because each of them is something the user needs
// shown rather than an error to swallow. An error is returned only when the
// payload itself cannot be produced.
func (e *Engine) DeviceState() (string, error) {
	now := time.Now().Unix()

	cfg, err := agent.LoadConfig(e.configDir)
	if err != nil || cfg == nil || cfg.AgentID == "" {
		return toJSON(deviceStatePayload{State: "not_enrolled", CheckedAt: now})
	}

	serverURL := strings.TrimRight(cfg.ServerURL, "/")
	if serverURL == "" {
		serverURL = e.serverURL
	}
	if serverURL == "" || cfg.AuthToken == "" {
		// Enrolled on disk but with nothing to ask with: report what is known
		// rather than inventing a state.
		return toJSON(deviceStatePayload{
			Enrolled:  true,
			State:     "unknown",
			Error:     "this device has no server URL or agent credential to check with",
			CheckedAt: now,
		})
	}

	body, err := transport.NewClient(serverURL, cfg.AuthToken, cfg.AgentID).GetConfig()
	if err != nil {
		if isRevoked(err) {
			// The one server answer that is a state rather than a failure.
			return toJSON(deviceStatePayload{
				Enrolled:        true,
				State:           "revoked",
				ServerReachable: true,
				CheckedAt:       now,
			})
		}
		e.logger.Warn("device state: could not reach the server", zap.Error(err))
		return toJSON(deviceStatePayload{
			Enrolled:  true,
			State:     "unknown",
			Error:     err.Error(),
			CheckedAt: now,
		})
	}

	var st agentConfigState
	if err := json.Unmarshal(body, &st); err != nil {
		return toJSON(deviceStatePayload{
			Enrolled:        true,
			State:           "unknown",
			ServerReachable: true,
			Error:           fmt.Sprintf("could not read the server's answer: %v", err),
			CheckedAt:       now,
		})
	}

	state := st.EnrollmentStatus
	if state == "" {
		// A server older than this field answered. Enrolled and reachable is
		// all that can honestly be said.
		state = "unknown"
	}
	return toJSON(deviceStatePayload{
		Enrolled:        true,
		State:           state,
		DeviceTrusted:   st.DeviceTrusted && state == "active",
		ServerReachable: true,
		CheckedAt:       now,
	})
}

// isRevoked reports whether err is the server refusing this device outright.
func isRevoked(err error) bool {
	return errors.Is(err, transport.ErrAgentRevoked)
}
