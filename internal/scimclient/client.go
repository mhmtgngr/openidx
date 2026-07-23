// Package scimclient is a minimal SCIM 2.0 client: it speaks the wire protocol
// to a downstream service provider (Okta, Entra, Slack, GitHub, ...) so OpenIDX
// can provision users and groups OUT to SaaS apps.
//
// The package is deliberately persistence-agnostic. It knows nothing about
// OpenIDX's database or queue; callers hand it fully-formed SCIM resources and
// it performs the HTTP create/replace/patch/delete calls, translating SCIM
// error envelopes into typed Go errors. This keeps the protocol surface small,
// unit-testable against httptest, and reusable by the provisioning worker.
package scimclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SCIM 2.0 schema URNs (RFC 7643).
const (
	SchemaUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaPatchOp        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError          = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Name is the SCIM 2.0 complex name attribute (RFC 7643 §4.1.1).
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	MiddleName string `json:"middleName,omitempty"`
}

// Email is a SCIM 2.0 multi-valued email (RFC 7643 §4.1.2).
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// EnterpriseUser is the SCIM 2.0 enterprise user extension (RFC 7643 §4.3).
// Only the attributes OpenIDX emits are modeled.
type EnterpriseUser struct {
	EmployeeNumber string      `json:"employeeNumber,omitempty"`
	Department     string      `json:"department,omitempty"`
	Manager        *ManagerRef `json:"manager,omitempty"`
}

// ManagerRef references another User resource by its remote id.
type ManagerRef struct {
	Value       string `json:"value,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// User is a SCIM 2.0 User resource sent to / received from a target.
type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *Name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	Active      bool     `json:"active"`
	// Enterprise carries the enterprise extension under its schema URN key.
	Enterprise *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

// MemberRef is a member of a SCIM Group.
type MemberRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}

// Group is a SCIM 2.0 Group resource.
type Group struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	DisplayName string      `json:"displayName"`
	Members     []MemberRef `json:"members,omitempty"`
}

// PatchOp is a single SCIM PATCH operation (RFC 7644 §3.5.2).
type PatchOp struct {
	Op    string      `json:"op"` // add | remove | replace
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

// PatchRequest is a SCIM PATCH body.
type PatchRequest struct {
	Schemas    []string  `json:"schemas"`
	Operations []PatchOp `json:"Operations"`
}

// ServiceProviderConfig captures the subset of the target's advertised
// capabilities the client cares about (RFC 7643 §5). Used by Probe to decide
// whether PATCH is supported.
type ServiceProviderConfig struct {
	Patch struct {
		Supported bool `json:"supported"`
	} `json:"patch"`
	Filter struct {
		Supported  bool `json:"supported"`
		MaxResults int  `json:"maxResults,omitempty"`
	} `json:"filter"`
}

// Config configures a Client for one target endpoint.
type Config struct {
	// BaseURL is the SCIM 2.0 service-provider root, e.g.
	// https://api.slack.com/scim/v2 (no trailing slash required).
	BaseURL string
	// Bearer is the static bearer token used for Authorization. For OAuth2
	// targets the caller resolves an access token and passes it here.
	Bearer string
	// HTTPClient is optional; a sane default with a timeout is used if nil.
	HTTPClient *http.Client
	// UserAgent overrides the default User-Agent header.
	UserAgent string
}

// Client speaks SCIM 2.0 to one target service provider.
type Client struct {
	baseURL   string
	bearer    string
	http      *http.Client
	userAgent string
}

// New builds a Client. BaseURL must be non-empty.
func New(cfg Config) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("scimclient: BaseURL is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = "OpenIDX-SCIM-Client/1.0"
	}
	return &Client{baseURL: base, bearer: cfg.Bearer, http: hc, userAgent: ua}, nil
}

// APIError is a typed SCIM error response (non-2xx).
type APIError struct {
	StatusCode int
	ScimType   string
	Detail     string
	// Body is the raw response body, for diagnostics when it is not a SCIM
	// error envelope.
	Body string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("scim: %d %s: %s", e.StatusCode, e.ScimType, e.Detail)
	}
	return fmt.Sprintf("scim: %d: %s", e.StatusCode, strings.TrimSpace(e.Body))
}

// IsNotFound reports whether err is an APIError with HTTP 404. Callers use this
// to treat "already gone" as success when deprovisioning.
func IsNotFound(err error) bool {
	ae, ok := err.(*APIError)
	return ok && ae.StatusCode == http.StatusNotFound
}

// IsConflict reports whether err is an APIError with HTTP 409 (resource already
// exists). Callers use this to reconcile a lost create.
func IsConflict(err error) bool {
	ae, ok := err.(*APIError)
	return ok && ae.StatusCode == http.StatusConflict
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("scimclient: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("scimclient: build request: %w", err)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("scimclient: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseAPIError(resp.StatusCode, respBody)
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("scimclient: decode response: %w", err)
		}
	}
	return nil
}

func parseAPIError(status int, body []byte) *APIError {
	ae := &APIError{StatusCode: status, Body: string(body)}
	var env struct {
		ScimType string `json:"scimType"`
		Detail   string `json:"detail"`
		Status   string `json:"status"`
	}
	if json.Unmarshal(body, &env) == nil {
		ae.ScimType = env.ScimType
		ae.Detail = env.Detail
	}
	return ae
}

// Probe fetches the target's ServiceProviderConfig. It doubles as a
// connectivity/auth test: a nil error means the base URL is reachable and the
// bearer token is accepted.
func (c *Client) Probe(ctx context.Context) (*ServiceProviderConfig, error) {
	var spc ServiceProviderConfig
	if err := c.do(ctx, http.MethodGet, "/ServiceProviderConfig", nil, &spc); err != nil {
		return nil, err
	}
	return &spc, nil
}

// CreateUser POSTs a new User and returns the created resource (with its remote
// id populated).
func (c *Client) CreateUser(ctx context.Context, u *User) (*User, error) {
	ensureUserSchemas(u)
	var out User
	if err := c.do(ctx, http.MethodPost, "/Users", u, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReplaceUser PUTs the full User representation at the given remote id.
func (c *Client) ReplaceUser(ctx context.Context, remoteID string, u *User) (*User, error) {
	ensureUserSchemas(u)
	var out User
	if err := c.do(ctx, http.MethodPut, "/Users/"+remoteID, u, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetUserActive PATCHes only the active flag. This is the canonical
// deactivate/reactivate operation and is preferred over DELETE for
// deprovisioning because it is reversible and preserves the remote resource.
func (c *Client) SetUserActive(ctx context.Context, remoteID string, active bool) error {
	patch := PatchRequest{
		Schemas: []string{SchemaPatchOp},
		Operations: []PatchOp{
			{Op: "replace", Path: "active", Value: active},
		},
	}
	return c.do(ctx, http.MethodPatch, "/Users/"+remoteID, patch, nil)
}

// PatchUser applies arbitrary PATCH operations to a User.
func (c *Client) PatchUser(ctx context.Context, remoteID string, ops []PatchOp) error {
	patch := PatchRequest{Schemas: []string{SchemaPatchOp}, Operations: ops}
	return c.do(ctx, http.MethodPatch, "/Users/"+remoteID, patch, nil)
}

// DeleteUser DELETEs a User. Treats 404 as success (already gone).
func (c *Client) DeleteUser(ctx context.Context, remoteID string) error {
	err := c.do(ctx, http.MethodDelete, "/Users/"+remoteID, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// CreateGroup POSTs a new Group and returns the created resource.
func (c *Client) CreateGroup(ctx context.Context, g *Group) (*Group, error) {
	ensureGroupSchemas(g)
	var out Group
	if err := c.do(ctx, http.MethodPost, "/Groups", g, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReplaceGroup PUTs the full Group representation at the given remote id.
func (c *Client) ReplaceGroup(ctx context.Context, remoteID string, g *Group) (*Group, error) {
	ensureGroupSchemas(g)
	var out Group
	if err := c.do(ctx, http.MethodPut, "/Groups/"+remoteID, g, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchGroup applies PATCH operations to a Group (e.g. add/remove members).
func (c *Client) PatchGroup(ctx context.Context, remoteID string, ops []PatchOp) error {
	patch := PatchRequest{Schemas: []string{SchemaPatchOp}, Operations: ops}
	return c.do(ctx, http.MethodPatch, "/Groups/"+remoteID, patch, nil)
}

// DeleteGroup DELETEs a Group. Treats 404 as success.
func (c *Client) DeleteGroup(ctx context.Context, remoteID string) error {
	err := c.do(ctx, http.MethodDelete, "/Groups/"+remoteID, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

func ensureUserSchemas(u *User) {
	if len(u.Schemas) == 0 {
		u.Schemas = []string{SchemaUser}
	}
	if u.Enterprise != nil && !containsSchema(u.Schemas, SchemaEnterpriseUser) {
		u.Schemas = append(u.Schemas, SchemaEnterpriseUser)
	}
}

func ensureGroupSchemas(g *Group) {
	if len(g.Schemas) == 0 {
		g.Schemas = []string{SchemaGroup}
	}
}

func containsSchema(schemas []string, want string) bool {
	for _, s := range schemas {
		if s == want {
			return true
		}
	}
	return false
}
