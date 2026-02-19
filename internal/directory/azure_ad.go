package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AzureADConnector manages Microsoft Graph API connections for Azure AD / Entra ID
type AzureADConnector struct {
	cfg    AzureADConfig
	logger *zap.Logger
	token  *azureToken
	client *http.Client
}

type azureToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

// NewAzureADConnector creates a new Azure AD connector
func NewAzureADConnector(cfg AzureADConfig, logger *zap.Logger) *AzureADConnector {
	return &AzureADConnector{
		cfg:    cfg,
		logger: logger.With(zap.String("component", "azure-ad-connector")),
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// TestConnection verifies token acquisition and basic /users query
func (c *AzureADConnector) TestConnection(ctx context.Context) error {
	if err := c.ensureToken(ctx); err != nil {
		return fmt.Errorf("failed to acquire Azure AD token: %w", err)
	}

	// Verify we can query the /users endpoint
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://graph.microsoft.com/v1.0/users?$top=1&$select=id", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.AccessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to query Microsoft Graph: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Microsoft Graph returned %d: %s", resp.StatusCode, string(body))
	}

	c.logger.Info("Azure AD connection test successful", zap.String("tenant_id", c.cfg.TenantID))
	return nil
}

// SearchUsers fetches all users from Azure AD via Microsoft Graph API
func (c *AzureADConnector) SearchUsers(ctx context.Context) ([]UserRecord, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	selectFields := "id,userPrincipalName,mail,givenName,surname,displayName,accountEnabled"
	endpoint := fmt.Sprintf("https://graph.microsoft.com/v1.0/users?$select=%s&$top=999", selectFields)
	if c.cfg.UserFilter != "" {
		endpoint += "&$filter=" + url.QueryEscape(c.cfg.UserFilter)
	}

	var allUsers []UserRecord
	nextLink := endpoint

	for nextLink != "" {
		users, next, err := c.fetchUsersPage(ctx, nextLink)
		if err != nil {
			return nil, err
		}
		allUsers = append(allUsers, users...)
		nextLink = next
	}

	c.logger.Debug("Azure AD user search completed", zap.Int("count", len(allUsers)))
	return allUsers, nil
}

// SearchUsersIncremental uses delta query to get users changed since last sync
func (c *AzureADConnector) SearchUsersIncremental(ctx context.Context, deltaLink string) ([]UserRecord, string, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, "", err
	}

	endpoint := deltaLink
	if endpoint == "" {
		// Initial delta query
		selectFields := "id,userPrincipalName,mail,givenName,surname,displayName,accountEnabled"
		endpoint = fmt.Sprintf("https://graph.microsoft.com/v1.0/users/delta?$select=%s", selectFields)
		if c.cfg.UserFilter != "" {
			endpoint += "&$filter=" + url.QueryEscape(c.cfg.UserFilter)
		}
	}

	var allUsers []UserRecord
	var newDeltaLink string
	nextLink := endpoint

	for nextLink != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextLink, nil)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token.AccessToken)

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("delta query failed: %w", err)
		}

		var result graphDeltaResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, "", fmt.Errorf("failed to decode delta response: %w", err)
		}
		resp.Body.Close()

		for _, u := range result.Value {
			allUsers = append(allUsers, mapGraphUser(u, c.cfg.AttributeMapping))
		}

		nextLink = result.NextLink
		if result.DeltaLink != "" {
			newDeltaLink = result.DeltaLink
		}
	}

	c.logger.Debug("Azure AD delta query completed",
		zap.Int("changed_users", len(allUsers)),
		zap.Bool("has_delta_link", newDeltaLink != ""))
	return allUsers, newDeltaLink, nil
}

// SearchGroups fetches all groups from Azure AD via Microsoft Graph API
func (c *AzureADConnector) SearchGroups(ctx context.Context) ([]GroupRecord, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	endpoint := "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description&$top=999"
	if c.cfg.GroupFilter != "" {
		endpoint += "&$filter=" + url.QueryEscape(c.cfg.GroupFilter)
	}

	var allGroups []GroupRecord
	nextLink := endpoint

	for nextLink != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextLink, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token.AccessToken)

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("group query failed: %w", err)
		}

		var result graphGroupsResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode groups response: %w", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Microsoft Graph returned %d for groups", resp.StatusCode)
		}

		for _, g := range result.Value {
			allGroups = append(allGroups, GroupRecord{
				DN:          g.ID, // Use Azure objectId as DN equivalent
				Name:        g.DisplayName,
				Description: g.Description,
			})
		}

		nextLink = result.NextLink
	}

	c.logger.Debug("Azure AD group search completed", zap.Int("count", len(allGroups)))
	return allGroups, nil
}

// SearchGroupMembers fetches members for a group via Microsoft Graph API
func (c *AzureADConnector) SearchGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members?$select=id", groupID)
	var memberIDs []string
	nextLink := endpoint

	for nextLink != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", nextLink, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.token.AccessToken)

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("group members query failed: %w", err)
		}

		var result graphMembersResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode members response: %w", err)
		}
		resp.Body.Close()

		for _, m := range result.Value {
			memberIDs = append(memberIDs, m.ID)
		}

		nextLink = result.NextLink
	}

	return memberIDs, nil
}

// ResetPassword resets a user's password via Microsoft Graph API
func (c *AzureADConnector) ResetPassword(ctx context.Context, userObjectID, newPassword string) error {
	if err := c.ensureToken(ctx); err != nil {
		return err
	}

	// Use the update user endpoint to set a new password
	endpoint := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", userObjectID)
	body := map[string]interface{}{
		"passwordProfile": map[string]interface{}{
			"password":                      newPassword,
			"forceChangePasswordNextSignIn": true,
		},
	}

	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "PATCH", endpoint, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("password reset request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("password reset failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	c.logger.Info("Azure AD password reset successful", zap.String("user_id", userObjectID))
	return nil
}

// ensureToken acquires or refreshes the OAuth2 access token via client credentials flow
func (c *AzureADConnector) ensureToken(ctx context.Context) error {
	if c.token != nil && time.Now().Before(c.token.ExpiresAt) {
		return nil
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.cfg.TenantID)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token acquisition failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	c.token = &azureToken{
		AccessToken: tokenResp.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second), // refresh 60s before expiry
	}

	c.logger.Debug("Azure AD token acquired", zap.String("tenant_id", c.cfg.TenantID))
	return nil
}

// fetchUsersPage fetches a single page of users and returns users + nextLink
func (c *AzureADConnector) fetchUsersPage(ctx context.Context, endpoint string) ([]UserRecord, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token.AccessToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("user query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("Microsoft Graph returned %d: %s", resp.StatusCode, string(body))
	}

	var result graphUsersResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("failed to decode users response: %w", err)
	}

	var users []UserRecord
	for _, u := range result.Value {
		users = append(users, mapGraphUser(u, c.cfg.AttributeMapping))
	}

	return users, result.NextLink, nil
}

// Graph API response types

type graphUsersResponse struct {
	Value    []graphUser `json:"value"`
	NextLink string      `json:"@odata.nextLink"`
}

type graphDeltaResponse struct {
	Value     []graphUser `json:"value"`
	NextLink  string      `json:"@odata.nextLink"`
	DeltaLink string      `json:"@odata.deltaLink"`
}

type graphUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	DisplayName       string `json:"displayName"`
	AccountEnabled    bool   `json:"accountEnabled"`
}

type graphGroupsResponse struct {
	Value    []graphGroup `json:"value"`
	NextLink string       `json:"@odata.nextLink"`
}

type graphGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

type graphMembersResponse struct {
	Value    []graphMember `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

type graphMember struct {
	ID string `json:"id"`
}

// mapGraphUser converts a Graph API user to our UserRecord
func mapGraphUser(u graphUser, mapping AttributeMapping) UserRecord {
	record := UserRecord{
		ExternalID: u.ID,
		DN:         u.ID, // Use Azure objectId as the DN equivalent for consistency
	}

	// Azure AD attribute names are fixed from the Graph API, so we map directly
	// The mapping config tells us which Graph field maps to which OpenIDX field
	// For Azure AD, defaults are: userPrincipalName→username, mail→email, etc.
	m := mapping
	if m.Username == "" || m.Username == "userPrincipalName" {
		record.Username = u.UserPrincipalName
	} else if m.Username == "mail" {
		record.Username = u.Mail
	} else {
		record.Username = u.UserPrincipalName
	}

	record.Email = u.Mail
	if record.Email == "" {
		record.Email = u.UserPrincipalName // Fallback to UPN
	}

	record.FirstName = u.GivenName
	record.LastName = u.Surname
	record.DisplayName = u.DisplayName

	return record
}
