package ziti

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ListServices retrieves all services from the Ziti controller.
func (mc *MgmtClient) ListServices(ctx context.Context) ([]ServiceInfo, error) {
	data, status, err := mc.Request(ctx, "GET", "/edge/management/v1/services?limit=500", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list services: unexpected status %d", status)
	}

	var resp struct {
		Data []ServiceInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse services: %w", err)
	}
	return resp.Data, nil
}

// GetServiceByID retrieves a single service by its Ziti ID.
func (mc *MgmtClient) GetServiceByID(ctx context.Context, zitiID string) (*ServiceInfo, error) {
	data, status, err := mc.Request(ctx, "GET",
		fmt.Sprintf("/edge/management/v1/services/%s", zitiID), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get service %s: unexpected status %d", zitiID, status)
	}

	var resp struct {
		Data ServiceInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse service: %w", err)
	}
	return &resp.Data, nil
}

// CreateService creates a new Ziti service.
func (mc *MgmtClient) CreateService(ctx context.Context, name string, attrs []string, configs []string) (string, error) {
	payload := map[string]interface{}{
		"name":               name,
		"roleAttributes":     attrs,
		"encryptionRequired": true,
	}
	if len(configs) > 0 {
		payload["configs"] = configs
	}
	body, _ := json.Marshal(payload)

	data, status, err := mc.Request(ctx, "POST", "/edge/management/v1/services", body)
	if err != nil {
		return "", fmt.Errorf("create service: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("create service: unexpected status %d: %s", status, string(data))
	}

	return parseIDFromResponse(data)
}

// DeleteService deletes a Ziti service by ID.
func (mc *MgmtClient) DeleteService(ctx context.Context, zitiID string) error {
	_, status, err := mc.Request(ctx, "DELETE",
		fmt.Sprintf("/edge/management/v1/services/%s", zitiID), nil)
	if err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("delete service: unexpected status %d", status)
	}
	return nil
}

// ListIdentities retrieves all identities from the Ziti controller.
func (mc *MgmtClient) ListIdentities(ctx context.Context) ([]IdentityInfo, error) {
	data, status, err := mc.Request(ctx, "GET", "/edge/management/v1/identities?limit=500", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list identities: unexpected status %d", status)
	}

	var resp struct {
		Data []IdentityInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}
	return resp.Data, nil
}

// CreateIdentity creates a new Ziti identity with OTT enrollment.
func (mc *MgmtClient) CreateIdentity(ctx context.Context, name, identityType string, attrs []string) (zitiID, enrollmentJWT string, err error) {
	if identityType == "" {
		identityType = "Device"
	}
	if attrs == nil {
		attrs = []string{}
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":           name,
		"type":           identityType,
		"isAdmin":        false,
		"roleAttributes": attrs,
		"enrollment":     map[string]interface{}{"ott": true},
	})

	data, status, err := mc.Request(ctx, "POST", "/edge/management/v1/identities", body)
	if err != nil {
		return "", "", fmt.Errorf("create identity: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", "", fmt.Errorf("create identity: unexpected status %d: %s", status, string(data))
	}

	var resp struct {
		Data struct {
			ID         string                 `json:"id"`
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", "", fmt.Errorf("parse identity: %w", err)
	}

	enrollmentJWT = extractOTTJWT(resp.Data.Enrollment)

	// If JWT not in create response, fetch it
	if enrollmentJWT == "" {
		enrollmentJWT, _ = mc.GetIdentityEnrollmentJWT(ctx, resp.Data.ID)
	}

	return resp.Data.ID, enrollmentJWT, nil
}

// DeleteIdentity deletes a Ziti identity by ID.
func (mc *MgmtClient) DeleteIdentity(ctx context.Context, zitiID string) error {
	_, status, err := mc.Request(ctx, "DELETE",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return fmt.Errorf("delete identity: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("delete identity: unexpected status %d", status)
	}
	return nil
}

// GetIdentityEnrollmentJWT retrieves the enrollment JWT for an identity.
func (mc *MgmtClient) GetIdentityEnrollmentJWT(ctx context.Context, zitiID string) (string, error) {
	data, status, err := mc.Request(ctx, "GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("get identity: unexpected status %d", status)
	}

	var resp struct {
		Data struct {
			Enrollment map[string]interface{} `json:"enrollment"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", err
	}

	jwt := extractOTTJWT(resp.Data.Enrollment)
	if jwt == "" {
		return "", fmt.Errorf("no enrollment JWT available for identity %s", zitiID)
	}
	return jwt, nil
}

// PatchIdentityRoleAttributes updates the role attributes of a Ziti identity.
func (mc *MgmtClient) PatchIdentityRoleAttributes(ctx context.Context, zitiID string, attrs []string) error {
	body, _ := json.Marshal(map[string]interface{}{"roleAttributes": attrs})
	_, status, err := mc.Request(ctx, "PATCH",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), body)
	if err != nil {
		return fmt.Errorf("patch identity attributes: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("patch identity attributes: unexpected status %d", status)
	}
	return nil
}

// GetIdentityRoleAttributes retrieves the current role attributes for an identity.
func (mc *MgmtClient) GetIdentityRoleAttributes(ctx context.Context, zitiID string) ([]string, error) {
	data, status, err := mc.Request(ctx, "GET",
		fmt.Sprintf("/edge/management/v1/identities/%s", zitiID), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get identity: unexpected status %d", status)
	}

	var resp struct {
		Data struct {
			RoleAttributes []string `json:"roleAttributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return resp.Data.RoleAttributes, nil
}

// CreateServicePolicy creates a Bind or Dial service policy.
func (mc *MgmtClient) CreateServicePolicy(ctx context.Context, name, policyType string, serviceRoles, identityRoles []string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":          name,
		"type":          policyType,
		"semantic":      "AnyOf",
		"serviceRoles":  serviceRoles,
		"identityRoles": identityRoles,
	})

	data, status, err := mc.Request(ctx, "POST", "/edge/management/v1/service-policies", body)
	if err != nil {
		return "", fmt.Errorf("create service policy: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("create service policy: unexpected status %d: %s", status, string(data))
	}

	return parseIDFromResponse(data)
}

// DeleteServicePolicy deletes a service policy by ID.
func (mc *MgmtClient) DeleteServicePolicy(ctx context.Context, zitiID string) error {
	_, status, err := mc.Request(ctx, "DELETE",
		fmt.Sprintf("/edge/management/v1/service-policies/%s", zitiID), nil)
	if err != nil {
		return fmt.Errorf("delete service policy: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("delete service policy: unexpected status %d", status)
	}
	return nil
}

// UpdateServicePolicy updates an existing service policy.
func (mc *MgmtClient) UpdateServicePolicy(ctx context.Context, zitiID, name, policyType string, serviceRoles, identityRoles []string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"name":          name,
		"type":          policyType,
		"semantic":      "AnyOf",
		"serviceRoles":  serviceRoles,
		"identityRoles": identityRoles,
	})
	_, status, err := mc.Request(ctx, "PUT",
		fmt.Sprintf("/edge/management/v1/service-policies/%s", zitiID), body)
	if err != nil {
		return fmt.Errorf("update service policy: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("update service policy: unexpected status %d", status)
	}
	return nil
}

// CreateConfig creates a new Ziti config object.
func (mc *MgmtClient) CreateConfig(ctx context.Context, name, configTypeID string, data interface{}) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"name":         name,
		"configTypeId": configTypeID,
		"data":         data,
	})

	respData, status, err := mc.Request(ctx, "POST", "/edge/management/v1/configs", body)
	if err != nil {
		return "", fmt.Errorf("create config: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("create config: unexpected status %d: %s", status, string(respData))
	}

	return parseIDFromResponse(respData)
}

// ListConfigTypes retrieves all config types from the controller.
func (mc *MgmtClient) ListConfigTypes(ctx context.Context) ([]ConfigTypeInfo, error) {
	data, status, err := mc.Request(ctx, "GET", "/edge/management/v1/config-types?limit=500", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list config types: unexpected status %d", status)
	}

	var resp struct {
		Data []ConfigTypeInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse config types: %w", err)
	}
	return resp.Data, nil
}

// CreateEdgeRouterPolicy creates an edge router policy (idempotent-safe — ignores conflict).
func (mc *MgmtClient) CreateEdgeRouterPolicy(ctx context.Context, name string, edgeRouterRoles, identityRoles []string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"name":            name,
		"edgeRouterRoles": edgeRouterRoles,
		"identityRoles":   identityRoles,
	})
	_, _, err := mc.Request(ctx, "POST", "/edge/management/v1/edge-router-policies", body)
	return err
}

// CreateServiceEdgeRouterPolicy creates a service-edge-router policy.
func (mc *MgmtClient) CreateServiceEdgeRouterPolicy(ctx context.Context, name string, serviceRoles, edgeRouterRoles []string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"name":            name,
		"semantic":        "AnyOf",
		"serviceRoles":    serviceRoles,
		"edgeRouterRoles": edgeRouterRoles,
	})
	_, _, err := mc.Request(ctx, "POST", "/edge/management/v1/service-edge-router-policies", body)
	return err
}

// GetVersion checks connectivity and returns the controller version info.
func (mc *MgmtClient) GetVersion(ctx context.Context) (map[string]interface{}, error) {
	data, status, err := mc.Request(ctx, "GET", "/edge/management/v1/version", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get version: unexpected status %d", status)
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result, nil
}

// ListCAs retrieves certificate authorities from the controller.
func (mc *MgmtClient) ListCAs(ctx context.Context) ([]CAInfo, error) {
	data, status, err := mc.Request(ctx, "GET", "/edge/management/v1/cas", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list CAs: unexpected status %d", status)
	}

	var resp struct {
		Data []CAInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse CAs: %w", err)
	}
	return resp.Data, nil
}

// ListSessions retrieves sessions with an optional filter.
func (mc *MgmtClient) ListSessions(ctx context.Context, filter string, limit int) ([]SessionInfo, error) {
	path := "/edge/management/v1/sessions"
	if filter != "" || limit > 0 {
		params := url.Values{}
		if filter != "" {
			params.Set("filter", filter)
		}
		if limit > 0 {
			params.Set("limit", fmt.Sprintf("%d", limit))
		}
		path += "?" + params.Encode()
	}

	data, status, err := mc.Request(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list sessions: unexpected status %d", status)
	}

	var resp struct {
		Data []SessionInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse sessions: %w", err)
	}
	return resp.Data, nil
}

// ReEnrollIdentity triggers re-enrollment for a Ziti identity (certificate rotation).
func (mc *MgmtClient) ReEnrollIdentity(ctx context.Context, zitiID string) error {
	_, status, err := mc.Request(ctx, "POST",
		fmt.Sprintf("/edge/management/v1/identities/%s/re-enroll", zitiID), nil)
	if err != nil {
		return fmt.Errorf("re-enroll identity: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusNoContent {
		return fmt.Errorf("re-enroll identity: unexpected status %d", status)
	}
	return nil
}

// FindIdentitiesByFilter finds identities matching a Ziti filter expression.
func (mc *MgmtClient) FindIdentitiesByFilter(ctx context.Context, filter string) ([]IdentityInfo, error) {
	path := fmt.Sprintf("/edge/management/v1/identities?filter=%s", url.QueryEscape(filter))
	data, status, err := mc.Request(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("find identities: unexpected status %d", status)
	}

	var resp struct {
		Data []IdentityInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}
	return resp.Data, nil
}

// --- helpers ---

func parseIDFromResponse(data []byte) (string, error) {
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("parse response ID: %w", err)
	}
	return resp.Data.ID, nil
}

func extractOTTJWT(enrollment map[string]interface{}) string {
	if ott, ok := enrollment["ott"].(map[string]interface{}); ok {
		if jwt, ok := ott["jwt"].(string); ok {
			return jwt
		}
	}
	return ""
}
