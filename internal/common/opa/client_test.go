// Package opa provides tests for the Open Policy Agent client
package opa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestNewClient verifies client initialization with various configurations
func TestNewClient(t *testing.T) {
	t.Run("Creates client with valid URL", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient("http://localhost:8281", logger)

		assert.NotNil(t, client)
		assert.Equal(t, "http://localhost:8281", client.baseURL)
		assert.Equal(t, "/v1/data/openidx/authz", client.policyPath)
		assert.NotNil(t, client.httpClient)
		assert.NotNil(t, client.logger)
		assert.NotNil(t, client.ssrfValidator)
	})

	t.Run("Creates client with HTTPS URL", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient("https://opa.example.com", logger)

		assert.Equal(t, "https://opa.example.com", client.baseURL)
	})

	t.Run("Handles invalid URL gracefully", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient("://invalid-url", logger)

		// Client should still be created
		assert.NotNil(t, client)

		// But should log a warning
		found := false
		for _, log := range logs.All() {
			if log.Message == "Failed to parse OPA URL for SSRF validation" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected warning log for invalid URL")
	})

	t.Run("Parses hostname for SSRF validation", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient("http://opa.internal:8281", logger)

		assert.NotNil(t, client.ssrfValidator)
		assert.Len(t, client.ssrfValidator.AllowedDomains, 1)
		assert.Equal(t, "opa.internal", client.ssrfValidator.AllowedDomains[0])
	})

	t.Run("Configures SSRF to allow private IPs", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient("http://localhost:8281", logger)

		assert.False(t, client.ssrfValidator.BlockPrivateIPs, "OPA runs on private network")
		assert.False(t, client.ssrfValidator.BlockLocalhost, "OPA may run on localhost in dev")
	})
}

// TestInputSerialization verifies input structures are properly serialized
func TestInputSerialization(t *testing.T) {
	t.Run("Serializes full input", func(t *testing.T) {
		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"admin", "editor"},
				Groups:        []string{"group-a", "group-b"},
				TenantID:      "tenant-abc",
				Authenticated: true,
			},
			Resource: ResourceContext{
				Type:  "document",
				Owner: "user-456",
			},
			Method: "GET",
			Path:   "/api/v1/documents/123",
		}

		data, err := json.Marshal(input)
		require.NoError(t, err)

		var decoded Input
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, input.User.ID, decoded.User.ID)
		assert.Equal(t, input.User.Roles, decoded.User.Roles)
		assert.Equal(t, input.User.Groups, decoded.User.Groups)
		assert.Equal(t, input.User.TenantID, decoded.User.TenantID)
		assert.Equal(t, input.User.Authenticated, decoded.User.Authenticated)
		assert.Equal(t, input.Resource.Type, decoded.Resource.Type)
		assert.Equal(t, input.Resource.Owner, decoded.Resource.Owner)
		assert.Equal(t, input.Method, decoded.Method)
		assert.Equal(t, input.Path, decoded.Path)
	})

	t.Run("Serializes minimal input", func(t *testing.T) {
		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"viewer"},
				Authenticated: true,
			},
			Method: "GET",
			Path:   "/api/v1/public",
		}

		data, err := json.Marshal(input)
		require.NoError(t, err)

		var decoded Input
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.User.Groups)
		assert.Empty(t, decoded.User.TenantID)
		assert.Empty(t, decoded.Resource.Type)
		assert.Empty(t, decoded.Resource.Owner)
	})

	t.Run("Serializes unauthenticated user", func(t *testing.T) {
		input := Input{
			User: UserContext{
				ID:            "",
				Roles:         []string{},
				Authenticated: false,
			},
			Method: "GET",
			Path:   "/api/v1/public",
		}

		data, err := json.Marshal(input)
		require.NoError(t, err)

		var decoded Input
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.User.Authenticated)
		assert.Empty(t, decoded.User.Roles)
	})
}

// TestDecisionSerialization verifies decision structures are properly deserialized
func TestDecisionSerialization(t *testing.T) {
	t.Run("Deserializes allow decision", func(t *testing.T) {
		jsonData := `{"result": {"allow": true}}`

		var resp opaResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Result.Allow)
		assert.Empty(t, resp.Result.Deny)
	})

	t.Run("Deserializes deny decision with reasons", func(t *testing.T) {
		jsonData := `{"result": {"allow": false, "deny": ["missing_role", "insufficient_permissions"]}}`

		var resp opaResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.False(t, resp.Result.Allow)
		assert.Equal(t, []string{"missing_role", "insufficient_permissions"}, resp.Result.Deny)
	})

	t.Run("Deserializes decision with empty deny list", func(t *testing.T) {
		jsonData := `{"result": {"allow": true, "deny": []}}`

		var resp opaResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Result.Allow)
		assert.Empty(t, resp.Result.Deny)
	})
}

// TestAuthorizeRequest tests the authorize endpoint communication
func TestAuthorizeRequest(t *testing.T) {
	t.Run("Successful authorization request", func(t *testing.T) {
		// Mock OPA server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request method
			assert.Equal(t, http.MethodPost, r.Method)

			// Verify path
			assert.Equal(t, "/v1/data/openidx/authz", r.URL.Path)

			// Verify content type
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			// Decode and verify request body
			var reqBody map[string]interface{}
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)

			receivedInput, ok := reqBody["input"].(map[string]interface{})
			require.True(t, ok)

			// Verify input structure
			assert.NotNil(t, receivedInput)

			// Send successful response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{
					"allow": true,
				},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"admin"},
				Authenticated: true,
			},
			Method: "GET",
			Path:   "/api/v1/users",
		}

		decision, err := client.Authorize(context.Background(), input)

		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.True(t, decision.Allow)
		assert.Empty(t, decision.Deny)
	})

	t.Run("Authorization denied", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{
					"allow": false,
					"deny":  []string{"insufficient_permissions"},
				},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"viewer"},
				Authenticated: true,
			},
			Method: "DELETE",
			Path:   "/api/v1/users/456",
		}

		decision, err := client.Authorize(context.Background(), input)

		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.False(t, decision.Allow)
		assert.Equal(t, []string{"insufficient_permissions"}, decision.Deny)
	})

	t.Run("Handles context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Delay response to allow cancellation
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"allow": true},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		_, err := client.Authorize(ctx, input)
		assert.Error(t, err)
	})

	t.Run("Handles timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Delay beyond client timeout
			time.Sleep(6 * time.Second)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"allow": true},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		// The HTTP client has a 5-second timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := client.Authorize(ctx, input)
		assert.Error(t, err)
	})

	t.Run("Handles HTTP error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		_, err := client.Authorize(context.Background(), input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("Handles malformed response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		_, err := client.Authorize(context.Background(), input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decode OPA response")
	})

	t.Run("Handles network error", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		// Use an invalid URL that will fail to connect
		client := NewClient("http://localhost:9999", logger)

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		_, err := client.Authorize(context.Background(), input)
		assert.Error(t, err)

		// Should log a warning
		found := false
		for _, log := range logs.All() {
			if log.Message == "OPA request failed" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("Sends correct input payload", func(t *testing.T) {
		receivedInput := make(chan map[string]interface{}, 1)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)
			receivedInput <- reqBody

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"allow": true},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"admin", "editor"},
				Groups:        []string{"group-a"},
				TenantID:      "tenant-abc",
				Authenticated: true,
			},
			Resource: ResourceContext{
				Type:  "document",
				Owner: "user-456",
			},
			Method: "PUT",
			Path:   "/api/v1/documents/123",
		}

		_, err := client.Authorize(context.Background(), input)
		require.NoError(t, err)

		reqBody := <-receivedInput
		inputData, ok := reqBody["input"].(map[string]interface{})
		require.True(t, ok)

		// Verify all fields are sent
		user := inputData["user"].(map[string]interface{})
		assert.Equal(t, "user-123", user["id"])
		assert.Equal(t, []interface{}{"admin", "editor"}, user["roles"])
		assert.Equal(t, []interface{}{"group-a"}, user["groups"])
		assert.Equal(t, "tenant-abc", user["tenant_id"])
		assert.Equal(t, true, user["authenticated"])

		resource := inputData["resource"].(map[string]interface{})
		assert.Equal(t, "document", resource["type"])
		assert.Equal(t, "user-456", resource["owner"])

		assert.Equal(t, "PUT", inputData["method"])
		assert.Equal(t, "/api/v1/documents/123", inputData["path"])
	})
}

// TestSSRFValidation tests SSRF protection in OPA client
func TestSSRFValidation(t *testing.T) {
	t.Run("Blocks requests to disallowed domains", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		// Create client with allowed domain
		client := NewClient("http://opa.internal:8281", logger)

		// Try to make request to different domain by modifying baseURL
		// This simulates config manipulation attack
		client.baseURL = "http://evil.com"

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		_, err := client.Authorize(context.Background(), input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SSRF validation failed")

		// Check error was logged
		found := false
		for _, log := range logs.All() {
			if log.Message == "OPA URL failed SSRF validation" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("Allows requests to configured domain", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"allow": true},
			})
		}))
		defer server.Close()

		// Parse server URL to get hostname
		parsedURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		// Verify the domain is in allowed list
		assert.Contains(t, client.ssrfValidator.AllowedDomains, parsedURL.Hostname())

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		_, err = client.Authorize(context.Background(), input)
		assert.NoError(t, err)
	})

	t.Run("Blocks invalid URL schemes", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient("http://opa.internal:8281", logger)

		// Try to use file:// scheme
		client.baseURL = "file:///etc/passwd"

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		_, err := client.Authorize(context.Background(), input)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SSRF validation failed")
	})
}

// TestConcurrentEvaluation tests concurrent access to the OPA client
func TestConcurrentEvaluation(t *testing.T) {
	t.Run("Concurrent authorize requests", func(t *testing.T) {
		requestCount := atomic.Int32{}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount.Add(1)
			// Add small delay to increase likelihood of race conditions
			time.Sleep(10 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{
					"allow": true,
				},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		const numRequests = 50
		errChan := make(chan error, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				input := Input{
					User: UserContext{
						ID:            fmt.Sprintf("user-%d", idx),
						Roles:         []string{"viewer"},
						Authenticated: true,
					},
					Method: "GET",
					Path:   fmt.Sprintf("/api/v1/resource/%d", idx),
				}

				_, err := client.Authorize(context.Background(), input)
				errChan <- err
			}(i)
		}

		// Collect results
		errors := 0
		for i := 0; i < numRequests; i++ {
			if err := <-errChan; err != nil {
				errors++
			}
		}

		// All requests should succeed
		assert.Equal(t, 0, errors)
		assert.Equal(t, int32(numRequests), requestCount.Load())
	})

	t.Run("Concurrent requests with mixed outcomes", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Decode request to make decision
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)
			input := reqBody["input"].(map[string]interface{})
			user := input["user"].(map[string]interface{})
			roles := user["roles"].([]interface{})

			// Allow only if user has admin role
			hasAdmin := false
			for _, role := range roles {
				if role == "admin" {
					hasAdmin = true
					break
				}
			}

			result := map[string]interface{}{
				"result": map[string]interface{}{
					"allow": hasAdmin,
				},
			}
			if !hasAdmin {
				result["result"].(map[string]interface{})["deny"] = []string{"missing_admin_role"}
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(result)
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		const numRequests = 50
		results := make(chan *Decision, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				roles := []string{"viewer"}
				if idx%2 == 0 {
					roles = []string{"admin", "viewer"}
				}

				input := Input{
					User: UserContext{
						ID:            fmt.Sprintf("user-%d", idx),
						Roles:         roles,
						Authenticated: true,
					},
					Method: "GET",
					Path:   "/api/v1/admin",
				}

				decision, _ := client.Authorize(context.Background(), input)
				results <- decision
			}(i)
		}

		// Count allowed/denied
		allowed := 0
		denied := 0
		for i := 0; i < numRequests; i++ {
			decision := <-results
			if decision.Allow {
				allowed++
			} else {
				denied++
			}
		}

		// Half should be allowed (even indices have admin role)
		assert.Equal(t, 25, allowed)
		assert.Equal(t, 25, denied)
	})
}

// TestTableDrivenAuthorize provides table-driven tests for various authorization scenarios
func TestTableDrivenAuthorize(t *testing.T) {
	tests := []struct {
		name           string
		input          Input
		responseBody   string
		responseStatus int
		wantAllow      bool
		wantDeny       []string
		wantErr        bool
		errContains    string
	}{
		{
			name: "admin user can delete",
			input: Input{
				User: UserContext{
					ID:            "user-1",
					Roles:         []string{"admin"},
					Authenticated: true,
				},
				Method: "DELETE",
				Path:   "/api/v1/users/123",
			},
			responseBody:   `{"result": {"allow": true}}`,
			responseStatus: http.StatusOK,
			wantAllow:      true,
		},
		{
			name: "viewer cannot delete",
			input: Input{
				User: UserContext{
					ID:            "user-2",
					Roles:         []string{"viewer"},
					Authenticated: true,
				},
				Method: "DELETE",
				Path:   "/api/v1/users/123",
			},
			responseBody:   `{"result": {"allow": false, "deny": ["insufficient_permissions"]}}`,
			responseStatus: http.StatusOK,
			wantAllow:      false,
			wantDeny:       []string{"insufficient_permissions"},
		},
		{
			name: "unauthenticated user can access public endpoint",
			input: Input{
				User: UserContext{
					ID:            "",
					Roles:         []string{},
					Authenticated: false,
				},
				Method: "GET",
				Path:   "/api/v1/public/health",
			},
			responseBody:   `{"result": {"allow": true}}`,
			responseStatus: http.StatusOK,
			wantAllow:      true,
		},
		{
			name: "user with tenant access",
			input: Input{
				User: UserContext{
					ID:            "user-3",
					Roles:         []string{"tenant_admin"},
					TenantID:      "tenant-abc",
					Authenticated: true,
				},
				Resource: ResourceContext{
					Type:  "report",
					Owner: "tenant-abc",
				},
				Method: "GET",
				Path:   "/api/v1/reports/123",
			},
			responseBody:   `{"result": {"allow": true}}`,
			responseStatus: http.StatusOK,
			wantAllow:      true,
		},
		{
			name: "cross-tenant access denied",
			input: Input{
				User: UserContext{
					ID:            "user-4",
					Roles:         []string{"tenant_admin"},
					TenantID:      "tenant-abc",
					Authenticated: true,
				},
				Resource: ResourceContext{
					Type:  "report",
					Owner: "tenant-xyz",
				},
				Method: "GET",
				Path:   "/api/v1/reports/456",
			},
			responseBody:   `{"result": {"allow": false, "deny": ["cross_tenant_access_forbidden"]}}`,
			responseStatus: http.StatusOK,
			wantAllow:      false,
			wantDeny:       []string{"cross_tenant_access_forbidden"},
		},
		{
			name: "OPA server error",
			input: Input{
				User: UserContext{
					ID:            "user-5",
					Roles:         []string{"admin"},
					Authenticated: true,
				},
				Method: "GET",
				Path:   "/api/v1/users",
			},
			responseBody:   `{"error": "policy compilation error"}`,
			responseStatus: http.StatusInternalServerError,
			wantErr:        true,
			errContains:    "500",
		},
		{
			name: "Multiple deny reasons",
			input: Input{
				User: UserContext{
					ID:            "user-6",
					Roles:         []string{},
					Authenticated: true,
				},
				Method: "POST",
				Path:   "/api/v1/admin/config",
			},
			responseBody:   `{"result": {"allow": false, "deny": ["missing_role", "insufficient_permissions", "require_mfa"]}}`,
			responseStatus: http.StatusOK,
			wantAllow:      false,
			wantDeny:       []string{"missing_role", "insufficient_permissions", "require_mfa"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			core, _ := observer.New(zap.InfoLevel)
			logger := zap.New(core)

			client := NewClient(server.URL, logger)

			decision, err := client.Authorize(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantAllow, decision.Allow)
				assert.Equal(t, tt.wantDeny, decision.Deny)
			}
		})
	}
}

// TestDecisionCachingBehavior tests that decisions are correctly retrieved
func TestDecisionCachingBehavior(t *testing.T) {
	t.Run("Same request gets fresh decision", func(t *testing.T) {
		requestCount := atomic.Int32{}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count := requestCount.Add(1)
			// Alternate allow/deny based on request count
			allow := count%2 == 1

			result := map[string]interface{}{
				"result": map[string]interface{}{
					"allow": allow,
				},
			}
			if !allow {
				result["result"].(map[string]interface{})["deny"] = []string{"alternating_deny"}
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(result)
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"viewer"},
				Authenticated: true,
			},
			Method: "GET",
			Path:   "/api/v1/test",
		}

		// Make multiple identical requests
		decisions := make([]*Decision, 5)
		for i := 0; i < 5; i++ {
			decision, err := client.Authorize(context.Background(), input)
			require.NoError(t, err)
			decisions[i] = decision
		}

		// Verify we made 5 requests (no client-side caching)
		assert.Equal(t, int32(5), requestCount.Load())

		// Verify decisions alternated (1st=true, 2nd=false, 3rd=true, etc.)
		for i := 0; i < 5; i++ {
			expectedAllow := (i%2 == 0) // 1st request (index 0) = true, 2nd (index 1) = false
			assert.Equal(t, expectedAllow, decisions[i].Allow, "Request %d should have allow=%v", i+1, expectedAllow)
		}
	})
}

// TestPolicyPath verifies the correct policy path is used
func TestPolicyPath(t *testing.T) {
	t.Run("Uses default policy path", func(t *testing.T) {
		receivedPath := make(chan string, 1)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedPath <- r.URL.Path
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"allow": true},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User: UserContext{ID: "user-123", Authenticated: true},
		}

		_, err := client.Authorize(context.Background(), input)
		require.NoError(t, err)

		path := <-receivedPath
		assert.Equal(t, "/v1/data/openidx/authz", path)
	})
}

// TestUnknownValues tests handling of unknown/partial values in OPA
func TestUnknownValues(t *testing.T) {
	t.Run("Handles partial evaluation results", func(t *testing.T) {
		// OPA can return undefined for unknown values
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate partial result where allow is undefined
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result": {"allow": false}}`))
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"unknown_role"},
				Authenticated: true,
			},
			Method: "GET",
			Path:   "/api/v1/unknown",
		}

		decision, err := client.Authorize(context.Background(), input)
		require.NoError(t, err)
		assert.False(t, decision.Allow)
	})

	t.Run("Handles missing fields in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Response missing deny field
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result": {"allow": false}}`))
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User:     UserContext{ID: "user-123", Authenticated: true},
			Method:   "GET",
			Path:     "/api/v1/test",
		}

		decision, err := client.Authorize(context.Background(), input)
		require.NoError(t, err)
		assert.False(t, decision.Allow)
		assert.Empty(t, decision.Deny) // Should be empty, not nil
	})
}

// TestComplexInputScenarios tests complex real-world scenarios
func TestComplexInputScenarios(t *testing.T) {
	t.Run("Resource owner access", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)
			input := reqBody["input"].(map[string]interface{})
			resource := input["resource"].(map[string]interface{})
			user := input["user"].(map[string]interface{})

			// Allow if user is resource owner
			isOwner := user["id"] == resource["owner"]

			result := map[string]interface{}{
				"result": map[string]interface{}{
					"allow": isOwner,
				},
			}
			if !isOwner {
				result["result"].(map[string]interface{})["deny"] = []string{"not_resource_owner"}
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(result)
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		// Owner access
		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"user"},
				Authenticated: true,
			},
			Resource: ResourceContext{
				Type:  "document",
				Owner: "user-123",
			},
			Method: "PUT",
			Path:   "/api/v1/documents/123",
		}

		decision, err := client.Authorize(context.Background(), input)
		require.NoError(t, err)
		assert.True(t, decision.Allow)

		// Non-owner access
		input.User.ID = "user-456"

		decision, err = client.Authorize(context.Background(), input)
		require.NoError(t, err)
		assert.False(t, decision.Allow)
		assert.Equal(t, []string{"not_resource_owner"}, decision.Deny)
	})

	t.Run("Group-based authorization", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody map[string]interface{}
			json.NewDecoder(r.Body).Decode(&reqBody)
			input := reqBody["input"].(map[string]interface{})
			user := input["user"].(map[string]interface{})
			groups := user["groups"].([]interface{})

			// Allow if user is in "finance" group
			inFinanceGroup := false
			for _, g := range groups {
				if g == "finance" {
					inFinanceGroup = true
					break
				}
			}

			result := map[string]interface{}{
				"result": map[string]interface{}{
					"allow": inFinanceGroup,
				},
			}
			if !inFinanceGroup {
				result["result"].(map[string]interface{})["deny"] = []string{"not_in_finance_group"}
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(result)
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		// User in finance group
		input := Input{
			User: UserContext{
				ID:            "user-123",
				Groups:        []string{"finance", "employees"},
				Authenticated: true,
			},
			Method: "GET",
			Path:   "/api/v1/financial-reports",
		}

		decision, err := client.Authorize(context.Background(), input)
		require.NoError(t, err)
		assert.True(t, decision.Allow)

		// User not in finance group
		input.User.Groups = []string{"engineering", "employees"}

		decision, err = client.Authorize(context.Background(), input)
		require.NoError(t, err)
		assert.False(t, decision.Allow)
		assert.Equal(t, []string{"not_in_finance_group"}, decision.Deny)
	})
}

// TestJSONMarhalingErrors tests input marshaling edge cases
func TestJSONMarshalingErrors(t *testing.T) {
	t.Run("Handles complex nested structures", func(t *testing.T) {
		core, _ := observer.New(zap.InfoLevel)
		_ = zap.New(core)

		// Create input with deeply nested data
		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         make([]string, 100), // Large roles array
				Groups:        make([]string, 50),
				Authenticated: true,
			},
		}

		// Marshal should still work
		_, err := json.Marshal(input)
		assert.NoError(t, err)
	})

	t.Run("Handles special characters in fields", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"result": map[string]interface{}{"allow": true},
			})
		}))
		defer server.Close()

		core, _ := observer.New(zap.InfoLevel)
		logger := zap.New(core)

		client := NewClient(server.URL, logger)

		input := Input{
			User: UserContext{
				ID:            "user-123",
				Roles:         []string{"admin\"evil", "role\nwith\nnewlines"},
				Authenticated: true,
			},
			Method: "GET",
			Path:   "/api/v1/normal",
		}

		// Should handle special characters properly
		_, err := client.Authorize(context.Background(), input)
		assert.NoError(t, err)
	})
}

// TestUserContextDefaults tests default values for UserContext
func TestUserContextDefaults(t *testing.T) {
	t.Run("Empty slices serialize correctly", func(t *testing.T) {
		user := UserContext{
			ID:            "user-123",
			Roles:         []string{},
			Groups:        nil,
			Authenticated: true,
		}

		data, err := json.Marshal(user)
		require.NoError(t, err)

		var decoded UserContext
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Roles)
		assert.Empty(t, decoded.Groups)
	})

	t.Run("Omitted fields serialize correctly", func(t *testing.T) {
		user := UserContext{
			ID:            "user-123",
			Roles:         []string{"admin"},
			Authenticated: true,
			// Groups and TenantID omitted
		}

		data, err := json.Marshal(user)
		require.NoError(t, err)

		// Check that omitted fields are not in JSON
		jsonStr := string(data)
		assert.NotContains(t, jsonStr, "groups")
		assert.NotContains(t, jsonStr, "tenant_id")
	})
}

// TestResourceContext tests resource context handling
func TestResourceContext(t *testing.T) {
	t.Run("Serializes full resource context", func(t *testing.T) {
		resource := ResourceContext{
			Type:  "document",
			Owner: "user-123",
		}

		data, err := json.Marshal(resource)
		require.NoError(t, err)

		var decoded ResourceContext
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, "document", decoded.Type)
		assert.Equal(t, "user-123", decoded.Owner)
	})

	t.Run("Empty resource context", func(t *testing.T) {
		resource := ResourceContext{}

		data, err := json.Marshal(resource)
		require.NoError(t, err)

		var decoded ResourceContext
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Type)
		assert.Empty(t, decoded.Owner)
	})
}

// Benchmark tests for performance measurement
func BenchmarkAuthorize(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{"allow": true},
		})
	}))
	defer server.Close()

	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	client := NewClient(server.URL, logger)

	input := Input{
		User: UserContext{
			ID:            "user-123",
			Roles:         []string{"admin"},
			Authenticated: true,
		},
		Method: "GET",
		Path:   "/api/v1/test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.Authorize(context.Background(), input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorizeConcurrent(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{"allow": true},
		})
	}))
	defer server.Close()

	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	client := NewClient(server.URL, logger)

	input := Input{
		User: UserContext{
			ID:            "user-123",
			Roles:         []string{"admin"},
			Authenticated: true,
		},
		Method: "GET",
		Path:   "/api/v1/test",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.Authorize(context.Background(), input)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkInputMarshal(b *testing.B) {
	input := Input{
		User: UserContext{
			ID:            "user-123",
			Roles:         []string{"admin", "editor", "viewer"},
			Groups:        []string{"group-a", "group-b"},
			TenantID:      "tenant-abc",
			Authenticated: true,
		},
		Resource: ResourceContext{
			Type:  "document",
			Owner: "user-456",
		},
		Method: "GET",
		Path:   "/api/v1/documents/123",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}
