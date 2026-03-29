package transport

// Transport defines the interface for agent-server communication.
// Both HTTP and Ziti transports implement this interface.
type Transport interface {
	Enroll(token string) (*EnrollResponse, error)
	ReportResults(data []byte) error
	GetConfig() ([]byte, error)
}
