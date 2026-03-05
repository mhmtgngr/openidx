package access

import (
	"context"

	pkgziti "github.com/openidx/openidx/pkg/ziti"
)

// ZitiManagerAdapter wraps the internal ZitiManager to satisfy pkgziti.Manager.
// This allows other services to depend on the clean interface while the internal
// implementation keeps its own types.
type ZitiManagerAdapter struct {
	inner *ZitiManager
}

// NewZitiManagerAdapter creates a new adapter around an existing ZitiManager.
func NewZitiManagerAdapter(zm *ZitiManager) *ZitiManagerAdapter {
	return &ZitiManagerAdapter{inner: zm}
}

func (a *ZitiManagerAdapter) IsInitialized() bool {
	return a.inner.IsInitialized()
}

func (a *ZitiManagerAdapter) Close() {
	a.inner.Close()
}

func (a *ZitiManagerAdapter) CreateService(ctx context.Context, name string, attrs []string) (string, error) {
	return a.inner.CreateService(ctx, name, attrs)
}

func (a *ZitiManagerAdapter) DeleteService(ctx context.Context, zitiID string) error {
	return a.inner.DeleteService(ctx, zitiID)
}

func (a *ZitiManagerAdapter) ListServices(ctx context.Context) ([]pkgziti.ServiceInfo, error) {
	internal, err := a.inner.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]pkgziti.ServiceInfo, len(internal))
	for i, s := range internal {
		result[i] = pkgziti.ServiceInfo{
			ID:             s.ID,
			Name:           s.Name,
			RoleAttributes: s.RoleAttributes,
			Protocol:       s.Protocol,
			Configs:        s.Configs,
		}
	}
	return result, nil
}

func (a *ZitiManagerAdapter) GetServiceByName(name string) (*pkgziti.ServiceInfo, error) {
	s, err := a.inner.GetServiceByName(name)
	if err != nil {
		return nil, err
	}
	return &pkgziti.ServiceInfo{
		ID:             s.ID,
		Name:           s.Name,
		RoleAttributes: s.RoleAttributes,
		Protocol:       s.Protocol,
		Configs:        s.Configs,
	}, nil
}

func (a *ZitiManagerAdapter) GetService(zitiID string) (*pkgziti.ServiceInfo, error) {
	s, err := a.inner.GetService(zitiID)
	if err != nil {
		return nil, err
	}
	return &pkgziti.ServiceInfo{
		ID:             s.ID,
		Name:           s.Name,
		RoleAttributes: s.RoleAttributes,
		Protocol:       s.Protocol,
		Configs:        s.Configs,
	}, nil
}

func (a *ZitiManagerAdapter) CreateIdentity(ctx context.Context, name, identityType string, attrs []string) (string, string, error) {
	return a.inner.CreateIdentity(ctx, name, identityType, attrs)
}

func (a *ZitiManagerAdapter) DeleteIdentity(ctx context.Context, zitiID string) error {
	return a.inner.DeleteIdentity(ctx, zitiID)
}

func (a *ZitiManagerAdapter) ListIdentities(ctx context.Context) ([]pkgziti.IdentityInfo, error) {
	internal, err := a.inner.ListIdentities(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]pkgziti.IdentityInfo, len(internal))
	for i, id := range internal {
		result[i] = pkgziti.IdentityInfo{
			ID:             id.ID,
			Name:           id.Name,
			Type:           id.Type,
			RoleAttributes: id.Attributes,
		}
	}
	return result, nil
}

func (a *ZitiManagerAdapter) GetIdentityEnrollmentJWT(ctx context.Context, zitiID string) (string, error) {
	return a.inner.GetIdentityEnrollmentJWT(ctx, zitiID)
}

func (a *ZitiManagerAdapter) PatchIdentityRoleAttributes(ctx context.Context, zitiID string, attrs []string) error {
	return a.inner.PatchIdentityRoleAttributes(ctx, zitiID, attrs)
}

func (a *ZitiManagerAdapter) GetIdentityRoleAttributes(ctx context.Context, zitiID string) ([]string, error) {
	return a.inner.GetIdentityRoleAttributes(ctx, zitiID)
}

func (a *ZitiManagerAdapter) CreateServicePolicy(ctx context.Context, name, policyType string, serviceRoles, identityRoles []string) (string, error) {
	return a.inner.CreateServicePolicy(ctx, name, policyType, serviceRoles, identityRoles)
}

func (a *ZitiManagerAdapter) DeleteServicePolicy(ctx context.Context, zitiID string) error {
	return a.inner.DeleteServicePolicy(ctx, zitiID)
}

func (a *ZitiManagerAdapter) UpdateServicePolicy(ctx context.Context, zitiID, name, policyType string, serviceRoles, identityRoles []string) error {
	return a.inner.UpdateServicePolicy(ctx, zitiID, name, policyType, serviceRoles, identityRoles)
}

func (a *ZitiManagerAdapter) EnsureServiceEdgeRouterPolicy(ctx context.Context, name string, serviceRoles, edgeRouterRoles []string) error {
	return a.inner.EnsureServiceEdgeRouterPolicy(ctx, name, serviceRoles, edgeRouterRoles)
}

func (a *ZitiManagerAdapter) SetupZitiForRoute(ctx context.Context, routeID, serviceName, host string, port int) error {
	return a.inner.SetupZitiForRoute(ctx, routeID, serviceName, host, port)
}

func (a *ZitiManagerAdapter) TeardownZitiForRoute(ctx context.Context, routeID string) error {
	return a.inner.TeardownZitiForRoute(ctx, routeID)
}

func (a *ZitiManagerAdapter) HostService(serviceName, targetHost string, targetPort int) error {
	return a.inner.HostService(serviceName, targetHost, targetPort)
}

func (a *ZitiManagerAdapter) StopHostingService(serviceName string) {
	a.inner.StopHostingService(serviceName)
}

func (a *ZitiManagerAdapter) HostAllServices(ctx context.Context) {
	a.inner.HostAllServices(ctx)
}

func (a *ZitiManagerAdapter) GetControllerVersion(ctx context.Context) (map[string]interface{}, error) {
	return a.inner.GetControllerVersion(ctx)
}

func (a *ZitiManagerAdapter) CheckControllerHealth(ctx context.Context) (bool, error) {
	return a.inner.CheckControllerHealth(ctx)
}

func (a *ZitiManagerAdapter) IsControllerAvailable() bool {
	return a.inner.IsControllerAvailable()
}

func (a *ZitiManagerAdapter) MgmtRequest(method, path string, body []byte) ([]byte, int, error) {
	return a.inner.MgmtRequest(method, path, body)
}

func (a *ZitiManagerAdapter) MgmtRequestWithCircuitBreaker(method, path string, body []byte) ([]byte, int, error) {
	return a.inner.MgmtRequestWithCircuitBreaker(method, path, body)
}

// Compile-time assertion
var _ pkgziti.Manager = (*ZitiManagerAdapter)(nil)
