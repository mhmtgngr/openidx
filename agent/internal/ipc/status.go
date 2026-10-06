// Package ipc is the local link between the SYSTEM service (device identity +
// posture + Ziti) and the user-session tray. The service serves read-only
// status over a named pipe; the tray queries it. Windows-only transport
// (go-winio) with non-Windows stubs.
package ipc

// PipeName is the Windows named pipe the service listens on.
const PipeName = `\\.\pipe\openidx-agent`

// pipeSDDL is the DACL the service puts on the pipe. Authenticated Users (AU)
// get GENERIC_READ and nothing else; the service (SYSTEM) and Administrators
// keep full control.
//
// It used to grant AU GENERIC_ALL. On a named pipe that mask carries
// FILE_CREATE_PIPE_INSTANCE (0x4, the same bit as FILE_APPEND_DATA), so any
// signed-in user could create a further instance of \\.\pipe\openidx-agent
// and answer the tray's next query with a status of their choosing: "not
// revoked", "no admin is watching". GENERIC_READ maps to FILE_GENERIC_READ,
// which has no instance-creation, WRITE_DAC or WRITE_OWNER bit, and it is all
// the tray needs: the service writes the JSON, the tray only reads it (Query
// opens the pipe for GENERIC_READ alone, so the client side matches).
const pipeSDDL = "D:P(A;;GR;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)"

// Status is the read-only snapshot the service exposes to the tray.
type Status struct {
	Enrolled     bool   `json:"enrolled"`
	AgentID      string `json:"agent_id,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	ServerURL    string `json:"server_url,omitempty"`
	ZitiEnrolled bool   `json:"ziti_enrolled"`
	// Revoked is true once the server has refused this device as revoked by
	// an administrator. The tray shows it and offers no connections.
	Revoked          bool   `json:"revoked,omitempty"`
	ComplianceStatus string `json:"compliance_status,omitempty"`
	LastReportAt     string `json:"last_report_at,omitempty"`
	// RemoteSupportActive is true while an admin remote-support session is live
	// for this device. The tray raises the "An OpenIDX admin can see and control
	// this device" banner when set. RemoteSupportControlled adds that the admin
	// currently holds control (view vs control).
	RemoteSupportActive     bool `json:"remote_support_active,omitempty"`
	RemoteSupportControlled bool `json:"remote_support_controlled,omitempty"`
}
