// Package governance provides tests for Zero Trust policy storage
package governance

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/database"
)

// setupTestDB creates a test database container
func setupTestDB(t *testing.T) (*database.PostgresDB, func()) {
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
		return nil, func() {}
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, func() {}
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container port: %v", err)
		return nil, func() {}
	}

	connString := "postgres://test:test@" + host + ":" + port.Port() + "/testdb?sslmode=disable"

	db, err := database.NewPostgres(connString)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to connect to test database: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		db.Close()
		container.Terminate(ctx)
	}

	return db, cleanup
}

// TestZTPolicyStore_CreateAndGet tests creating and retrieving a policy
func TestZTPolicyStore_CreateAndGet(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	policy := ZTPolicy{
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

	created, err := store.Create(ctx, policy, "test-user")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if created.ID == "" {
		t.Error("Expected policy ID to be set")
	}

	if created.Version != 1 {
		t.Errorf("Expected version 1, got %d", created.Version)
	}

	// Get the policy
	retrieved, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.Name != policy.Name {
		t.Errorf("Expected name %s, got %s", policy.Name, retrieved.Name)
	}

	if retrieved.Effect != policy.Effect {
		t.Errorf("Expected effect %s, got %s", policy.Effect, retrieved.Effect)
	}

	if retrieved.Conditions.Operator != policy.Conditions.Operator {
		t.Errorf("Expected operator %s, got %s", policy.Conditions.Operator, retrieved.Conditions.Operator)
	}
}

// TestZTPolicyStore_UpdateVersioning tests versioning on update
func TestZTPolicyStore_UpdateVersioning(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	policy := ZTPolicy{
		Name:        "Test Policy",
		Description: "Original description",
		Effect:      EffectAllow,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Priority: 50,
	}

	created, err := store.Create(ctx, policy, "test-user")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update the policy
	created.Description = "Updated description"
	created.Priority = 100

	updated, err := store.Update(ctx, *created, "test-user2")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if updated.Version != 2 {
		t.Errorf("Expected version 2, got %d", updated.Version)
	}

	if updated.Description != "Updated description" {
		t.Errorf("Description was not updated")
	}

	if updated.Priority != 100 {
		t.Errorf("Priority was not updated")
	}

	// Check version history
	history, err := store.GetHistory(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}

	if len(history) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(history))
	}

	if history[0].Version != 2 {
		t.Errorf("Expected first version to be 2, got %d", history[0].Version)
	}

	if history[0].ChangeType != "updated" {
		t.Errorf("Expected change_type 'updated', got %s", history[0].ChangeType)
	}

	if history[0].ChangedBy != "test-user2" {
		t.Errorf("Expected changed_by 'test-user2', got %s", history[0].ChangedBy)
	}

	if history[1].Version != 1 {
		t.Errorf("Expected second version to be 1, got %d", history[1].Version)
	}

	if history[1].ChangeType != "created" {
		t.Errorf("Expected change_type 'created', got %s", history[1].ChangeType)
	}
}

// TestZTPolicyStore_List tests listing policies with filters
func TestZTPolicyStore_List(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	// Create multiple policies
	policies := []ZTPolicy{
		{
			Name:     "Allow Policy",
			Effect:   EffectAllow,
			Priority: 50,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.authenticated", Operator: OpEquals, Value: true},
				},
			},
			TenantID: "tenant1",
			Enabled:  true,
		},
		{
			Name:     "Deny Policy",
			Effect:   EffectDeny,
			Priority: 100,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.id", Operator: OpEquals, Value: "blocked"},
				},
			},
			TenantID: "tenant1",
			Enabled:  true,
		},
		{
			Name:     "Disabled Policy",
			Effect:   EffectAllow,
			Priority: 10,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.authenticated", Operator: OpEquals, Value: true},
				},
			},
			TenantID: "tenant2",
			Enabled:  false,
		},
	}

	for _, p := range policies {
		if _, err := store.Create(ctx, p, "test-user"); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// List all
	all, err := store.List(ctx, nil)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(all) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(all))
	}

	// Filter by tenant
	tenant1Policies, err := store.List(ctx, &PolicyFilter{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("List by tenant failed: %v", err)
	}

	if len(tenant1Policies) != 2 {
		t.Errorf("Expected 2 policies for tenant1, got %d", len(tenant1Policies))
	}

	// Filter by enabled
	enabled := true
	enabledPolicies, err := store.List(ctx, &PolicyFilter{Enabled: &enabled})
	if err != nil {
		t.Fatalf("List by enabled failed: %v", err)
	}

	if len(enabledPolicies) != 2 {
		t.Errorf("Expected 2 enabled policies, got %d", len(enabledPolicies))
	}

	// Filter by effect
	allowPolicies, err := store.List(ctx, &PolicyFilter{Effect: "allow"})
	if err != nil {
		t.Fatalf("List by effect failed: %v", err)
	}

	if len(allowPolicies) != 2 {
		t.Errorf("Expected 2 allow policies, got %d", len(allowPolicies))
	}

	// Combined filters
	combined, err := store.List(ctx, &PolicyFilter{
		TenantID: "tenant1",
		Enabled:  &enabled,
		Effect:   "allow",
	})
	if err != nil {
		t.Fatalf("List with combined filters failed: %v", err)
	}

	if len(combined) != 1 {
		t.Errorf("Expected 1 policy with combined filters, got %d", len(combined))
	}
}

// TestZTPolicyStore_Delete tests soft delete
func TestZTPolicyStore_Delete(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	policy := ZTPolicy{
		Name:     "Test Policy",
		Effect:   EffectAllow,
		Priority: 50,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Enabled: true,
	}

	created, err := store.Create(ctx, policy, "test-user")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Soft delete
	if err := store.Delete(ctx, created.ID, "test-user"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Policy should still exist but be disabled
	retrieved, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get after delete failed: %v", err)
	}

	if retrieved.Enabled {
		t.Error("Expected policy to be disabled after soft delete")
	}

	// Check history for delete event
	history, err := store.GetHistory(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}

	// Should have 'created' and 'deleted' entries
	if len(history) != 2 {
		t.Errorf("Expected 2 history entries, got %d", len(history))
	}

	if history[0].ChangeType != "deleted" {
		t.Errorf("Expected change_type 'deleted', got %s", history[0].ChangeType)
	}
}

// TestZTPolicyStore_SetEnabled tests enabling/disabling policies
func TestZTPolicyStore_SetEnabled(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	policy := ZTPolicy{
		Name:     "Test Policy",
		Effect:   EffectAllow,
		Priority: 50,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
		Enabled: true,
	}

	created, err := store.Create(ctx, policy, "test-user")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Disable
	if err := store.SetEnabled(ctx, created.ID, false, "test-user"); err != nil {
		t.Fatalf("SetEnabled false failed: %v", err)
	}

	retrieved, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved.Enabled {
		t.Error("Expected policy to be disabled")
	}

	// Enable
	if err := store.SetEnabled(ctx, created.ID, true, "test-user"); err != nil {
		t.Fatalf("SetEnabled true failed: %v", err)
	}

	retrieved, err = store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if !retrieved.Enabled {
		t.Error("Expected policy to be enabled")
	}

	// Check history
	history, err := store.GetHistory(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}

	// Should have: created, disabled, enabled
	if len(history) != 3 {
		t.Errorf("Expected 3 history entries, got %d", len(history))
	}
}

// TestZTPolicyStore_Count tests counting policies
func TestZTPolicyStore_Count(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	// Create policies
	for i := 0; i < 5; i++ {
		policy := ZTPolicy{
			Name:     "Test Policy",
			Effect:   EffectAllow,
			Priority: 50,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.authenticated", Operator: OpEquals, Value: true},
				},
			},
			TenantID: "tenant1",
			Enabled:  true,
		}
		if i >= 3 {
			policy.TenantID = "tenant2"
			policy.Enabled = false
		}
		if _, err := store.Create(ctx, policy, "test-user"); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Count all
	total, err := store.Count(ctx, nil)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}

	if total != 5 {
		t.Errorf("Expected count 5, got %d", total)
	}

	// Count by tenant
	tenant1Count, err := store.Count(ctx, &PolicyFilter{TenantID: "tenant1"})
	if err != nil {
		t.Fatalf("Count by tenant failed: %v", err)
	}

	if tenant1Count != 3 {
		t.Errorf("Expected tenant1 count 3, got %d", tenant1Count)
	}

	// Count enabled
	enabled := true
	enabledCount, err := store.Count(ctx, &PolicyFilter{Enabled: &enabled})
	if err != nil {
		t.Fatalf("Count enabled failed: %v", err)
	}

	if enabledCount != 3 {
		t.Errorf("Expected enabled count 3, got %d", enabledCount)
	}
}

// TestZTPolicyStore_LoadAllEvaluator tests loading policies into evaluator
func TestZTPolicyStore_LoadAllEvaluator(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	// Create policies
	policies := []ZTPolicy{
		{
			Name:     "Allow Policy",
			Effect:   EffectAllow,
			Priority: 50,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.authenticated", Operator: OpEquals, Value: true},
				},
			},
			Enabled: true,
		},
		{
			Name:     "Deny Policy",
			Effect:   EffectDeny,
			Priority: 100,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.id", Operator: OpEquals, Value: "blocked"},
				},
			},
			Enabled: true,
		},
		{
			Name:     "Disabled Policy",
			Effect:   EffectDeny,
			Priority: 200,
			Conditions: ConditionGroup{
				Operator: OpAnd,
				Conditions: []Condition{
					{Field: "subject.id", Operator: OpEquals, Value: "any"},
				},
			},
			Enabled: false, // Disabled
		},
	}

	for _, p := range policies {
		if _, err := store.Create(ctx, p, "test-user"); err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Load all enabled policies into evaluator
	eval, err := store.LoadAllEvaluator(ctx)
	if err != nil {
		t.Fatalf("LoadAllEvaluator failed: %v", err)
	}

	// Should have 2 policies (enabled only)
	loadedPolicies := eval.GetPolicies()
	if len(loadedPolicies) != 2 {
		t.Errorf("Expected 2 policies loaded, got %d", len(loadedPolicies))
	}

	// Test evaluation
	input := ZTPolicyInput{
		Subject:  Subject{ID: "user1", Authenticated: true},
		Resource: Resource{Type: "api"},
		Action:   "read",
		Context:  EvaluationContext{Time: time.Now()},
	}

	result := eval.Evaluate(input)
	if !result.Allowed {
		t.Error("Expected allow for authenticated user")
	}
}

// TestZTPolicyStore_GetByVersion tests retrieving specific versions
func TestZTPolicyStore_GetByVersion(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	policy := ZTPolicy{
		Name:        "Test Policy",
		Description: "Original",
		Effect:      EffectAllow,
		Priority:    50,
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
	}

	created, err := store.Create(ctx, policy, "test-user")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update to create version 2
	created.Description = "Updated"
	updated, err := store.Update(ctx, *created, "test-user")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Get version 1
	v1, err := store.GetByVersion(ctx, created.ID, 1)
	if err != nil {
		t.Fatalf("GetByVersion v1 failed: %v", err)
	}

	if v1.Description != "Original" {
		t.Errorf("Expected v1 description 'Original', got '%s'", v1.Description)
	}

	if v1.Version != 1 {
		t.Errorf("Expected version 1, got %d", v1.Version)
	}

	// Get version 2
	v2, err := store.GetByVersion(ctx, created.ID, 2)
	if err != nil {
		t.Fatalf("GetByVersion v2 failed: %v", err)
	}

	if v2.Description != "Updated" {
		t.Errorf("Expected v2 description 'Updated', got '%s'", v2.Description)
	}

	if v2.Version != 2 {
		t.Errorf("Expected version 2, got %d", v2.Version)
	}

	// Try to get non-existent version
	_, err = store.GetByVersion(ctx, created.ID, 999)
	if err == nil {
		t.Error("Expected error for non-existent version")
	}
}

// TestZTPolicyStore_GetByName tests retrieving policy by name
func TestZTPolicyStore_GetByName(t *testing.T) {
	db, cleanup := setupTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	logger := zaptest.NewLogger(t)
	store := NewZTPolicyStore(db, logger)

	ctx := context.Background()

	policy := ZTPolicy{
		Name:     "unique-policy-name",
		Effect:   EffectAllow,
		Priority: 50,
		TenantID: "tenant1",
		Conditions: ConditionGroup{
			Operator: OpAnd,
			Conditions: []Condition{
				{Field: "subject.authenticated", Operator: OpEquals, Value: true},
			},
		},
	}

	_, err := store.Create(ctx, policy, "test-user")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get by name
	retrieved, err := store.GetByName(ctx, "unique-policy-name", "tenant1")
	if err != nil {
		t.Fatalf("GetByName failed: %v", err)
	}

	if retrieved.Name != "unique-policy-name" {
		t.Errorf("Expected name 'unique-policy-name', got '%s'", retrieved.Name)
	}

	// Try with wrong tenant
	_, err = store.GetByName(ctx, "unique-policy-name", "tenant2")
	if err == nil {
		t.Error("Expected error when getting policy with wrong tenant")
	}
}
