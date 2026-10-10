package transport

import "net"

// Transport defines the interface for agent-server communication.
// Both HTTP and Ziti transports implement this interface.
type Transport interface {
	Enroll(token string) (*EnrollResponse, error)
	ReportResults(data []byte) error
	GetConfig() ([]byte, error)
	SendConsent(sessionID, decision string) error
	// DialServiceConn opens a raw connection to a named Ziti overlay service.
	// Returns an error for transports that are not Ziti-backed, so callers can
	// fall back to a public dial. Used by remote-support to carry the signaling
	// WebSocket over the overlay (zero-trust, no public port).
	DialServiceConn(serviceName string) (net.Conn, error)
}

// ReportResponder is a Transport that can hand back the body of the report
// response. The server may answer a report with policy for the device (an
// org_network_policy, for one); a transport that cannot return the body is
// still a Transport, and the agent then reads that policy from /agent/config
// alone.
type ReportResponder interface {
	ReportResultsResponse(data []byte) ([]byte, error)
}

// reportResponse posts a report over t and returns the response body when t
// can give one.
func reportResponse(t Transport, data []byte) ([]byte, error) {
	if rr, ok := t.(ReportResponder); ok {
		return rr.ReportResultsResponse(data)
	}
	return nil, t.ReportResults(data)
}
