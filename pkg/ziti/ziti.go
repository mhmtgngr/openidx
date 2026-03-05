package ziti

import "context"

// Manager defines the interface for OpenZiti integration.
// Services that need Ziti functionality depend on this interface rather than
// the concrete ZitiManager, enabling easier testing, mocking, and alternative
// implementations.
type Manager interface {
	// IsInitialized returns whether the Ziti SDK context is ready.
	IsInitialized() bool

	// Close releases all Ziti resources.
	Close()

	// Service CRUD
	CreateService(ctx context.Context, name string, attrs []string) (id string, err error)
	DeleteService(ctx context.Context, zitiID string) error
	ListServices(ctx context.Context) ([]ServiceInfo, error)
	GetServiceByName(serviceName string) (*ServiceInfo, error)
	GetService(zitiID string) (*ServiceInfo, error)

	// Identity CRUD
	CreateIdentity(ctx context.Context, name, identityType string, attrs []string) (zitiID, enrollmentJWT string, err error)
	DeleteIdentity(ctx context.Context, zitiID string) error
	ListIdentities(ctx context.Context) ([]IdentityInfo, error)
	GetIdentityEnrollmentJWT(ctx context.Context, zitiID string) (string, error)
	PatchIdentityRoleAttributes(ctx context.Context, zitiID string, attrs []string) error
	GetIdentityRoleAttributes(ctx context.Context, zitiID string) ([]string, error)

	// Policy management
	CreateServicePolicy(ctx context.Context, name, policyType string, serviceRoles, identityRoles []string) (id string, err error)
	DeleteServicePolicy(ctx context.Context, zitiID string) error
	UpdateServicePolicy(ctx context.Context, zitiID, name, policyType string, serviceRoles, identityRoles []string) error
	EnsureServiceEdgeRouterPolicy(ctx context.Context, name string, serviceRoles, edgeRouterRoles []string) error

	// Route lifecycle
	SetupZitiForRoute(ctx context.Context, routeID, serviceName, host string, port int) error
	TeardownZitiForRoute(ctx context.Context, routeID string) error

	// Service hosting
	HostService(serviceName, targetHost string, targetPort int) error
	StopHostingService(serviceName string)
	HostAllServices(ctx context.Context)

	// Controller health
	GetControllerVersion(ctx context.Context) (map[string]interface{}, error)
	CheckControllerHealth(ctx context.Context) (bool, error)
	IsControllerAvailable() bool

	// Management API passthrough (for advanced operations)
	MgmtRequest(method, path string, body []byte) ([]byte, int, error)
	MgmtRequestWithCircuitBreaker(method, path string, body []byte) ([]byte, int, error)
}
