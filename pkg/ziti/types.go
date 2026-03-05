// Package ziti provides a clean, reusable client for the OpenZiti management API.
// It decouples Ziti controller communication from application-specific logic,
// making it easier for any OpenIDX service to interact with the Ziti overlay.
package ziti

import "time"

// ServiceInfo represents a Ziti service from the management API.
type ServiceInfo struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	RoleAttributes []string `json:"roleAttributes"`
	Protocol       string   `json:"protocol,omitempty"`
	Configs        []string `json:"configs,omitempty"`
}

// IdentityInfo represents a Ziti identity from the management API.
type IdentityInfo struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	RoleAttributes []string `json:"roleAttributes"`
	EnrollmentJWT  string   `json:"enrollment_jwt,omitempty"`
}

// ServicePolicyInfo represents a Ziti service policy.
type ServicePolicyInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"` // "Bind" or "Dial"
	Semantic      string   `json:"semantic"`
	ServiceRoles  []string `json:"serviceRoles"`
	IdentityRoles []string `json:"identityRoles"`
}

// ConfigInfo represents a Ziti config object.
type ConfigInfo struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	ConfigTypeID string                 `json:"configTypeId"`
	Data         map[string]interface{} `json:"data"`
}

// ConfigTypeInfo represents a Ziti config type.
type ConfigTypeInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ControllerVersion holds the Ziti controller version info.
type ControllerVersion struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	BuildDate string `json:"buildDate"`
}

// CAInfo represents a Certificate Authority from the Ziti controller.
type CAInfo struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Fingerprint        string `json:"fingerprint"`
	CertPEM            string `json:"certPem"`
	IsVerified         bool   `json:"isVerified"`
	IsAutoCaEnrollment bool   `json:"isAutoCaEnrollmentEnabled"`
}

// SessionInfo represents a Ziti session.
type SessionInfo struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	IdentityID string    `json:"identityId"`
	ServiceID  string    `json:"serviceId"`
	CreatedAt  time.Time `json:"createdAt"`
}

// HostV1Config is the data payload for a host.v1 Ziti config.
type HostV1Config struct {
	Protocol          string              `json:"protocol"`
	Address           string              `json:"address"`
	Port              int                 `json:"port"`
	ForwardProtocol   bool                `json:"forwardProtocol"`
	AllowedProtocols  []string            `json:"allowedProtocols"`
	ForwardAddress    bool                `json:"forwardAddress"`
	AllowedAddresses  []string            `json:"allowedAddresses"`
	ForwardPort       bool                `json:"forwardPort"`
	AllowedPortRanges []PortRange         `json:"allowedPortRanges"`
}

// PortRange represents a Ziti port range.
type PortRange struct {
	Low  int `json:"low"`
	High int `json:"high"`
}
