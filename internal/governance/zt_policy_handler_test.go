// Package governance provides tests for Zero Trust policy HTTP handlers
package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/database"
)

// setupHandlerTest creates test database and handler
func setupHandlerTest(t *testing.T) (*database.PostgresDB, *ZTPolicyHandler, func()) {
	t.Helper()

	ctx := context.Background()

	// Start PostgreSQL container
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Failed to start test container: %v", err)
		return nil, nil, func() {}
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, nil, func() {}
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container port: %v", err)
		return nil, nil, func() {}
	}

	connString := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	db, err := database.NewPostgres(connString)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to connect to test database: %v", err)
		return nil, nil, func() {}
	}

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)
	handler := NewZTPolicyHandler(store, logger)

	// Reload evaluator to initialize
	if err := handler.RefreshEvaluator(ctx); err != nil {
		t.Logf("Warning: failed to refresh evaluator: %v", err)
	}

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, handler, cleanup
}

// TestZTPolicyHandler_CreatePolicy tests creating a policy via HTTP
func TestZTPolicyHandler_CreatePolicy(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	reqBody := CreatePolicyRequest{
		Name:        "Test Policy",
		Description: "A test policy",
		Effect:      EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "subject.authenticated",
					Operator: OpEquals,
					Value:    true,
				},
			},
		},
		Priority: 50,
		TenantID: "tenant1",
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d: %s", w.Code, w.Body.String())
	}

	var response ZTPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Name != reqBody.Name {
		t.Errorf("Expected name %s, got %s", reqBody.Name, response.Name)
	}

	if response.ID == "" {
		t.Error("Expected policy ID to be set")
	}

	if response.Version != 1 {
		t.Errorf("Expected version 1, got %d", response.Version)
	}
}

// TestZTPolicyHandler_ListPolicies tests listing policies
func TestZTPolicyHandler_ListPolicies(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create some policies first
	for i := 0; i < 3; i++ {
		reqBody := CreatePolicyRequest{
			Name:   "Policy " + string(rune('A'+i)),
			Effect: EffectAllow,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.authenticated", Operator: OpEquals, Value: true},
				},
			},
			Priority: 50,
		}
		body, _ := json.Marshal(reqBody)
		req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}

	// List policies
	req, _ := http.NewRequest("GET", "/api/v1/policies", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	count := int(response["count"].(float64))
	if count != 3 {
		t.Errorf("Expected 3 policies, got %d", count)
	}
}

// TestZTPolicyHandler_GetPolicy tests getting a single policy
func TestZTPolicyHandler_GetPolicy(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create a policy
	reqBody := CreatePolicyRequest{
		Name:   "Test Policy",
		Effect: EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Priority: 50,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var created ZTPolicy
	json.Unmarshal(w.Body.Bytes(), &created)

	// Get the policy
	req, _ = http.NewRequest("GET", "/api/v1/policies/"+created.ID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ZTPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.ID != created.ID {
		t.Errorf("Expected ID %s, got %s", created.ID, response.ID)
	}
}

// TestZTPolicyHandler_UpdatePolicy tests updating a policy
func TestZTPolicyHandler_UpdatePolicy(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create a policy
	reqBody := CreatePolicyRequest{
		Name:        "Original Name",
		Description: "Original Description",
		Effect:      EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Priority: 50,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var created ZTPolicy
	json.Unmarshal(w.Body.Bytes(), &created)

	// Update the policy
	updateReq := UpdatePolicyRequest{
		Name:        stringPtr("Updated Name"),
		Description: stringPtr("Updated Description"),
		Priority:    intPtr(100),
	}
	updateBody, _ := json.Marshal(updateReq)
	req, _ = http.NewRequest("PUT", "/api/v1/policies/"+created.ID, bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var response ZTPolicy
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if response.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", response.Name)
	}

	if response.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", response.Priority)
	}

	if response.Version != 2 {
		t.Errorf("Expected version 2 after update, got %d", response.Version)
	}
}

// TestZTPolicyHandler_DeletePolicy tests deleting a policy
func TestZTPolicyHandler_DeletePolicy(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create a policy
	reqBody := CreatePolicyRequest{
		Name:   "Test Policy",
		Effect: EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Priority: 50,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var created ZTPolicy
	json.Unmarshal(w.Body.Bytes(), &created)

	// Delete the policy
	req, _ = http.NewRequest("DELETE", "/api/v1/policies/"+created.ID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify it's disabled
	req, _ = http.NewRequest("GET", "/api/v1/policies/"+created.ID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response ZTPolicy
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Enabled {
		t.Error("Expected policy to be disabled after delete")
	}
}

// TestZTPolicyHandler_EvaluatePolicies tests the evaluate endpoint
func TestZTPolicyHandler_EvaluatePolicies(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create an allow policy
	reqBody := CreatePolicyRequest{
		Name:   "Allow Admins",
		Effect: EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "subject.authenticated",
					Operator: OpEquals,
					Value:    true,
				},
				{
					Field:    "subject.roles",
					Operator: OpHasRole,
					Value:    "admin",
				},
			},
		},
		Priority: 50,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Evaluate with admin user
	evalReq := EvaluateRequest{
		Subject: Subject{
			ID:            "user1",
			Type:          "user",
			Authenticated: true,
			Roles:         []string{"admin"},
		},
		Resource: Resource{
			ID:   "res1",
			Type: "document",
		},
		Action: "read",
		Context: EvaluationContext{
			IPAddress: "192.168.1.1",
			Time:      time.Now(),
		},
	}

	evalBody, _ := json.Marshal(evalReq)
	req, _ = http.NewRequest("POST", "/api/v1/policies/evaluate", bytes.NewReader(evalBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result ZTPolicyResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if !result.Allowed {
		t.Errorf("Expected access to be allowed, got: %+v", result)
	}

	if len(result.MatchedPolicies) != 1 {
		t.Errorf("Expected 1 matched policy, got %d", len(result.MatchedPolicies))
	}

	// Evaluate with non-admin user
	evalReq.Subject.Roles = []string{"user"}
	evalBody, _ = json.Marshal(evalReq)
	req, _ = http.NewRequest("POST", "/api/v1/policies/evaluate", bytes.NewReader(evalBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result2 ZTPolicyResult
	json.Unmarshal(w.Body.Bytes(), &result2)

	if result2.Allowed {
		t.Error("Expected access to be denied for non-admin user")
	}
}

// TestZTPolicyHandler_EvaluatePolicies_NestedConditions tests evaluation with nested conditions
func TestZTPolicyHandler_EvaluatePolicies_NestedConditions(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create a policy with nested conditions: (admin OR (user AND during_business_hours)) AND NOT suspicious_ip
	reqBody := CreatePolicyRequest{
		Name:   "Complex Policy",
		Effect: EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Groups: []ConditionGroup{
				{
					Operator: OpOr,
					Conditions: []Condition{
						{
							Field:    "subject.roles",
							Operator: OpHasRole,
							Value:    "admin",
						},
					},
					Groups: []ConditionGroup{
						{
							Operator: OpAnd,
							Conditions: []Condition{
								{
									Field:    "subject.roles",
									Operator: OpHasRole,
									Value:    "user",
								},
								{
									Field:    "context.time",
									Operator: OpTimeInRange,
									Value: map[string]string{
										"start": "09:00",
										"end":   "17:00",
									},
								},
							},
						},
					},
				},
				{
					Operator: OpNot,
					Conditions: []Condition{
						{
							Field:    "context.ip",
							Operator: OpIPInRange,
							Value:    "10.0.0.0/8",
						},
					},
				},
			},
		},
		Priority: 50,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	tests := []struct {
		name       string
		evalReq    EvaluateRequest
		expectedOK bool
	}{
		{
			name: "Admin from safe IP",
			evalReq: EvaluateRequest{
				Subject: Subject{
					ID:            "admin1",
					Authenticated: true,
					Roles:         []string{"admin"},
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "192.168.1.1",
					Time:      time.Now(),
				},
			},
			expectedOK: true,
		},
		{
			name: "Admin from blocked IP",
			evalReq: EvaluateRequest{
				Subject: Subject{
					ID:            "admin1",
					Authenticated: true,
					Roles:         []string{"admin"},
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "10.0.0.5",
					Time:      time.Now(),
				},
			},
			expectedOK: false,
		},
		{
			name: "User during business hours",
			evalReq: EvaluateRequest{
				Subject: Subject{
					ID:            "user1",
					Authenticated: true,
					Roles:         []string{"user"},
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "192.168.1.1",
					Time:      parseTime(t, "14:00"),
				},
			},
			expectedOK: true,
		},
		{
			name: "User outside business hours",
			evalReq: EvaluateRequest{
				Subject: Subject{
					ID:            "user1",
					Authenticated: true,
					Roles:         []string{"user"},
				},
				Resource: Resource{Type: "api"},
				Action:   "read",
				Context: EvaluationContext{
					IPAddress: "192.168.1.1",
					Time:      parseTime(t, "20:00"),
				},
			},
			expectedOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evalBody, _ := json.Marshal(tt.evalReq)
			req, _ := http.NewRequest("POST", "/api/v1/policies/evaluate", bytes.NewReader(evalBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
				return
			}

			var result ZTPolicyResult
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if result.Allowed != tt.expectedOK {
				t.Errorf("Expected allowed=%v, got allowed=%v. Reason: %s", tt.expectedOK, result.Allowed, result.Reason)
			}
		})
	}
}

// TestZTPolicyHandler_EvaluatePolicies_DenyPrecedence tests deny policy precedence
func TestZTPolicyHandler_EvaluatePolicies_DenyPrecedence(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create low priority allow policy
	allowReq := CreatePolicyRequest{
		Name:   "Allow All",
		Effect: EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Priority: 10,
	}
	allowBody, _ := json.Marshal(allowReq)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(allowBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Create high priority deny policy
	denyReq := CreatePolicyRequest{
		Name:   "Block Suspicious",
		Effect: EffectDeny,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{
					Field:    "context.ip",
					Operator: OpIPInRange,
					Value:    "192.168.1.0/24",
				},
			},
		},
		Priority: 100,
	}
	denyBody, _ := json.Marshal(denyReq)
	req, _ = http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(denyBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Evaluate from suspicious IP
	evalReq := EvaluateRequest{
		Subject: Subject{
			ID:            "user1",
			Authenticated: true,
		},
		Resource: Resource{Type: "api"},
		Action:   "read",
		Context: EvaluationContext{
			IPAddress: "192.168.1.50",
			Time:      time.Now(),
		},
	}

	evalBody, _ := json.Marshal(evalReq)
	req, _ = http.NewRequest("POST", "/api/v1/policies/evaluate", bytes.NewReader(evalBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var result ZTPolicyResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if result.Allowed {
		t.Error("High priority deny should override low priority allow")
	}

	if len(result.DeniedBy) == 0 {
		t.Error("Expected DenialBy to be set")
	}
}

// TestZTPolicyHandler_GetPolicyHistory tests version history endpoint
func TestZTPolicyHandler_GetPolicyHistory(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create a policy
	reqBody := CreatePolicyRequest{
		Name:   "Test Policy",
		Effect: EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Priority: 50,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var created ZTPolicy
	json.Unmarshal(w.Body.Bytes(), &created)

	// Update to create version 2
	updateReq := UpdatePolicyRequest{
		Priority: intPtr(100),
	}
	updateBody, _ := json.Marshal(updateReq)
	req, _ = http.NewRequest("PUT", "/api/v1/policies/"+created.ID, bytes.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Get history
	req, _ = http.NewRequest("GET", "/api/v1/policies/"+created.ID+"/versions", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	versions := response["versions"].([]interface{})
	count := len(versions)
	if count != 2 {
		t.Errorf("Expected 2 versions, got %d", count)
	}
}

// TestZTPolicyHandler_SetPolicyEnabled tests enable/disable endpoint
func TestZTPolicyHandler_SetPolicyEnabled(t *testing.T) {
	_, handler, cleanup := setupHandlerTest(t)
	if handler == nil {
		return
	}
	defer cleanup()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler.RegisterRoutes(router)

	// Create a policy
	reqBody := CreatePolicyRequest{
		Name:   "Test Policy",
		Effect: EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Priority: 50,
	}
	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var created ZTPolicy
	json.Unmarshal(w.Body.Bytes(), &created)

	// Disable the policy
	disableReq := struct {
		Enabled bool `json:"enabled"`
	}{Enabled: false}
	disableBody, _ := json.Marshal(disableReq)
	req, _ = http.NewRequest("PATCH", "/api/v1/policies/"+created.ID+"/enable", bytes.NewReader(disableBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify it's disabled
	req, _ = http.NewRequest("GET", "/api/v1/policies/"+created.ID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var response ZTPolicy
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Enabled {
		t.Error("Expected policy to be disabled")
	}

	// Enable the policy
	enableReq := struct {
		Enabled bool `json:"enabled"`
	}{Enabled: true}
	enableBody, _ := json.Marshal(enableReq)
	req, _ = http.NewRequest("PATCH", "/api/v1/policies/"+created.ID+"/enable", bytes.NewReader(enableBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Verify it's enabled
	req, _ = http.NewRequest("GET", "/api/v1/policies/"+created.ID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	json.Unmarshal(w.Body.Bytes(), &response)

	if !response.Enabled {
		t.Error("Expected policy to be enabled")
	}
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func parseTime(t *testing.T, timeStr string) time.Time {
	parsed, err := time.Parse("15:04", timeStr)
	if err != nil {
		t.Fatalf("Failed to parse time %s: %v", timeStr, err)
	}
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), parsed.Hour(), parsed.Minute(), 0, 0, time.Local)
}
