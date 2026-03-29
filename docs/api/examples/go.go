// OpenIDX API Examples - Go
//
// This package provides Go client examples for interacting with the OpenIDX API.
//
// To use these examples, first initialize the Go module:
//   go mod init openidx-client
//   go get github.com/google/uuid

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ============================================
// Types and Structures
// ============================================

// TokenResponse represents the OAuth 2.0 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope,omitempty"`
}

// User represents an OpenIDX user
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	RoleID    string    `json:"role_id,omitempty"`
	Active    bool      `json:"active"`
}

// Group represents an OpenIDX group
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	MemberCount int       `json:"member_count,omitempty"`
}

// APIError represents an API error response
type APIError struct {
	Code    string                 `json:"error"`
	Message string                 `json:"message"`
	Status  int                    `json:"status"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		Total  int `json:"total"`
		Page   int `json:"page"`
		PerPage int `json:"per_page"`
	} `json:"meta"`
}

// ============================================
// OAuth Client
// ============================================

// OAuthClient handles OAuth 2.0 authentication
type OAuthClient struct {
	clientID     string
	clientSecret string
	tokenURL     string
	scope        string
	httpClient   *http.Client
	tokenResp    *TokenResponse
	tokenExpiry  time.Time
	mu           chan struct{}
}

// NewOAuthClient creates a new OAuth client
func NewOAuthClient(clientID, clientSecret, tokenURL string) *OAuthClient {
	return &OAuthClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     tokenURL,
		scope:        "openid profile email",
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		mu:           make(chan struct{}, 1),
	}
}

// GetClientCredentialsToken obtains a token using client credentials grant
func (c *OAuthClient) GetClientCredentialsToken(ctx context.Context) (string, error) {
	payload := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     c.clientID,
		"client_secret": c.clientSecret,
		"scope":         c.scope,
	}

	return c.fetchToken(ctx, payload)
}

// GetPasswordGrantToken obtains a token using resource owner password grant
func (c *OAuthClient) GetPasswordGrantToken(ctx context.Context, username, password string) (string, error) {
	payload := map[string]string{
		"grant_type": "password",
		"username":   username,
		"password":   password,
		"scope":      c.scope,
	}

	return c.fetchToken(ctx, payload)
}

// RefreshAccessToken refreshes the access token
func (c *OAuthClient) RefreshAccessToken(ctx context.Context) (string, error) {
	if c.tokenResp == nil || c.tokenResp.RefreshToken == "" {
		return "", fmt.Errorf("no refresh token available")
	}

	payload := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": c.tokenResp.RefreshToken,
		"client_id":     c.clientID,
		"client_secret": c.clientSecret,
	}

	return c.fetchToken(ctx, payload)
}

// GetValidToken returns a valid access token, refreshing if necessary
func (c *OAuthClient) GetValidToken(ctx context.Context) (string, error) {
	c.mu <- struct{}{}         // acquire
	defer func() { <-c.mu }() // release

	if c.tokenResp == nil || time.Now().After(c.tokenExpiry.Add(-60*time.Second)) {
		if c.tokenResp != nil && c.tokenResp.RefreshToken != "" {
			return c.RefreshAccessToken(ctx)
		}
		return c.GetClientCredentialsToken(ctx)
	}

	return c.tokenResp.AccessToken, nil
}

func (c *OAuthClient) fetchToken(ctx context.Context, payload map[string]string) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s", resp.Status)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	c.tokenResp = &tokenResp
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return tokenResp.AccessToken, nil
}

// ============================================
// API Client
// ============================================

// Client is the main API client for OpenIDX services
type Client struct {
	oauth      *OAuthClient
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new API client
func NewClient(clientID, clientSecret, baseURL, tokenURL string) *Client {
	return &Client{
		oauth:      NewOAuthClient(clientID, clientSecret, tokenURL),
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Request makes an authenticated API request
func (c *Client) Request(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	token, err := c.oauth.GetValidToken(ctx)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err == nil {
			return nil, &apiErr
		}
		return nil, fmt.Errorf("request failed: %s", resp.Status)
	}

	return respBody, nil
}

// Get performs a GET request
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	return c.Request(ctx, "GET", path, nil)
}

// Post performs a POST request
func (c *Client) Post(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return c.Request(ctx, "POST", path, body)
}

// Put performs a PUT request
func (c *Client) Put(ctx context.Context, path string, body interface{}) ([]byte, error) {
	return c.Request(ctx, "PUT", path, body)
}

// Delete performs a DELETE request
func (c *Client) Delete(ctx context.Context, path string) ([]byte, error) {
	return c.Request(ctx, "DELETE", path, nil)
}

// ============================================
// Identity Service Client
// ============================================

// IdentityClient handles Identity Service API calls
type IdentityClient struct {
	*Client
}

// NewIdentityClient creates a new Identity Service client
func NewIdentityClient(clientID, clientSecret string) *IdentityClient {
	return &IdentityClient{
		Client: NewClient(
			clientID,
			clientSecret,
			"http://localhost:8001",
			"http://localhost:8006/oauth/token",
		),
	}
}

// ListUsers lists users with pagination
func (c *IdentityClient) ListUsers(ctx context.Context, offset, limit int) (*PaginatedResponse, error) {
	path := fmt.Sprintf("/api/v1/identity/users?offset=%d&limit=%d", offset, limit)
	body, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp PaginatedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetUser gets a user by ID
func (c *IdentityClient) GetUser(ctx context.Context, userID string) (*User, error) {
	path := fmt.Sprintf("/api/v1/identity/users/%s", userID)
	body, err := c.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// CreateUser creates a new user
type CreateUserRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Password  string `json:"password"`
	RoleID    string `json:"role_id,omitempty"`
}

func (c *IdentityClient) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	body, err := c.Post(ctx, "/api/v1/identity/users", req)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// UpdateUser updates a user
type UpdateUserRequest struct {
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Active    *bool   `json:"active,omitempty"`
}

func (c *IdentityClient) UpdateUser(ctx context.Context, userID string, req *UpdateUserRequest) (*User, error) {
	path := fmt.Sprintf("/api/v1/identity/users/%s", userID)
	body, err := c.Put(ctx, path, req)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// DeleteUser deletes a user
func (c *IdentityClient) DeleteUser(ctx context.Context, userID string) error {
	_, err := c.Delete(ctx, fmt.Sprintf("/api/v1/identity/users/%s", userID))
	return err
}

// ============================================
// Governance Service Client
// ============================================

// GovernanceClient handles Governance Service API calls
type GovernanceClient struct {
	*Client
}

// NewGovernanceClient creates a new Governance Service client
func NewGovernanceClient(clientID, clientSecret string) *GovernanceClient {
	return &GovernanceClient{
		Client: NewClient(
			clientID,
			clientSecret,
			"http://localhost:8002",
			"http://localhost:8006/oauth/token",
		),
	}
}

// CreateReviewRequest represents a create review request
type CreateReviewRequest struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	StartDate   time.Time   `json:"start_date"`
	EndDate     time.Time   `json:"end_date"`
	ReviewerIDs []string    `json:"reviewer_ids"`
	Scope       ReviewScope `json:"scope"`
}

// ReviewScope defines the scope of a review
type ReviewScope struct {
	Type    string `json:"type"` // group, application, user
	GroupID string `json:"group_id,omitempty"`
}

// CreateReview creates a new access review
func (c *GovernanceClient) CreateReview(ctx context.Context, req *CreateReviewRequest) (map[string]interface{}, error) {
	body, err := c.Post(ctx, "/api/v1/governance/reviews", req)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// ============================================
// Audit Service Client
// ============================================

// AuditClient handles Audit Service API calls
type AuditClient struct {
	*Client
}

// NewAuditClient creates a new Audit Service client
func NewAuditClient(clientID, clientSecret string) *AuditClient {
	return &AuditClient{
		Client: NewClient(
			clientID,
			clientSecret,
			"http://localhost:8004",
			"http://localhost:8006/oauth/token",
		),
	}
}

// QueryEventsParams represents query parameters for audit events
type QueryEventsParams struct {
	Limit    int
	Offset   int
	Sort     string
	Filter   string
	StartDate string
	EndDate   string
}

// QueryEvents queries audit events
func (c *AuditClient) QueryEvents(ctx context.Context, params *QueryEventsParams) ([]byte, error) {
	values := url.Values{}
	if params.Limit > 0 {
		values.Add("limit", strconv.Itoa(params.Limit))
	}
	if params.Offset > 0 {
		values.Add("offset", strconv.Itoa(params.Offset))
	}
	if params.Sort != "" {
		values.Add("sort", params.Sort)
	}
	if params.Filter != "" {
		values.Add("filter", params.Filter)
	}

	path := "/api/v1/audit/events?" + values.Encode()
	return c.Get(ctx, path)
}

// ============================================
// SCIM Client
// ============================================

// SCIMClient handles SCIM 2.0 API calls
type SCIMClient struct {
	*Client
}

// NewSCIMClient creates a new SCIM client
func NewSCIMClient(clientID, clientSecret string) *SCIMClient {
	return &SCIMClient{
		Client: NewClient(
			clientID,
			clientSecret,
			"http://localhost:8003",
			"http://localhost:8006/oauth/token",
		),
	}
}

// SCIMUser represents a SCIM 2.0 user
type SCIMUser struct {
	Schemas  []string    `json:"schemas"`
	ID       string      `json:"id,omitempty"`
	UserName string      `json:"userName"`
	Name     SCIMName    `json:"name"`
	Emails   []SCIMEmail `json:"emails"`
	Active   bool        `json:"active"`
}

// SCIMName represents a SCIM name
type SCIMName struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

// SCIMEmail represents a SCIM email
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

// CreateSCIMUser creates a SCIM user
func (c *SCIMClient) CreateSCIMUser(ctx context.Context, user *SCIMUser) (*SCIMUser, error) {
	user.Schemas = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}
	body, err := c.Post(ctx, "/scim/v2/Users", user)
	if err != nil {
		return nil, err
	}

	var result SCIMUser
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ============================================
// Usage Examples
// ============================================

func main() {
	ctx := context.Background()

	// Example 1: List users
	exampleListUsers(ctx)

	// Example 2: Create a user
	exampleCreateUser(ctx)

	// Example 3: Create access review
	exampleCreateAccessReview(ctx)

	// Example 4: Create SCIM user
	exampleCreateSCIMUser(ctx)
}

func exampleListUsers(ctx context.Context) {
	fmt.Println("=== Example: List Users ===")

	client := NewIdentityClient(
		"your_client_id",
		"your_client_secret",
	)

	resp, err := client.ListUsers(ctx, 0, 10)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Found %d users (total: %d)\n", len(resp.Data), resp.Meta.Total)
}

func exampleCreateUser(ctx context.Context) {
	fmt.Println("\n=== Example: Create User ===")

	client := NewIdentityClient(
		"your_client_id",
		"your_client_secret",
	)

	user, err := client.CreateUser(ctx, &CreateUserRequest{
		Email:     "newuser@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Password:  "SecurePassword123!",
		RoleID:    "role-id-here",
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Created user: %s (%s)\n", user.ID, user.Email)
}

func exampleCreateAccessReview(ctx context.Context) {
	fmt.Println("\n=== Example: Create Access Review ===")

	client := NewGovernanceClient(
		"your_client_id",
		"your_client_secret",
	)

	review, err := client.CreateReview(ctx, &CreateReviewRequest{
		Name:        "Q1 2024 Access Review",
		Description: "Quarterly access certification",
		StartDate:   time.Now(),
		EndDate:     time.Now().Add(30 * 24 * time.Hour),
		ReviewerIDs: []string{"reviewer-user-id"},
		Scope: ReviewScope{
			Type:    "group",
			GroupID: "group-id",
		},
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Created review: %v\n", review["id"])
}

func exampleCreateSCIMUser(ctx context.Context) {
	fmt.Println("\n=== Example: Create SCIM User ===")

	client := NewSCIMClient(
		"your_client_id",
		"your_client_secret",
	)

	user, err := client.CreateSCIMUser(ctx, &SCIMUser{
		UserName: "scim.user@example.com",
		Name: SCIMName{
			GivenName:  "SCIM",
			FamilyName: "User",
		},
		Emails: []SCIMEmail{{
			Value:   "scim.user@example.com",
			Type:    "work",
			Primary: true,
		}},
		Active: true,
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Created SCIM user: %s\n", user.ID)
}

// ============================================
// Helper Functions
// ============================================

// ParsePaginatedResponse parses a paginated response into a slice of the specified type
func ParsePaginatedResponse(data []byte, target interface{}) (*PaginatedResponse, error) {
	var resp PaginatedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}

	// Unmarshal data items into target slice
	if err := json.Unmarshal(data, target); err != nil {
		return nil, err
	}

	return &resp, nil
}

// WithQueryParam adds a query parameter to a path
func WithQueryParam(path, key, value string) string {
	separator := "?"
	if bytes.ContainsAny([]byte(path), "?") {
		separator = "&"
	}
	return fmt.Sprintf("%s%s%s=%s", path, separator, key, url.QueryEscape(value))
}
