// Package ipc is the local link between the SYSTEM service (device identity +
// posture + Ziti) and the user-session tray. The service serves read-only
// status over a named pipe; the tray queries it. Windows-only transport
// (go-winio) with non-Windows stubs.
package ipc

// PipeName is the Windows named pipe the service listens on.
const PipeName = `\\.\pipe\openidx-agent`

// Status is the read-only snapshot the service exposes to the tray.
type Status struct {
	Enrolled         bool   `json:"enrolled"`
	AgentID          string `json:"agent_id,omitempty"`
	DeviceID         string `json:"device_id,omitempty"`
	ServerURL        string `json:"server_url,omitempty"`
	ZitiEnrolled     bool   `json:"ziti_enrolled"`
	ComplianceStatus string `json:"compliance_status,omitempty"`
	LastReportAt     string `json:"last_report_at,omitempty"`
}
