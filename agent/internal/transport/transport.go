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
