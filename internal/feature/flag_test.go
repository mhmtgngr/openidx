// Package feature provides tests for the feature flag system
package feature

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	flag := &Flag{
		Name:        "test-flag",
		Enabled:     true,
		Percentage:  50,
		Description: "Test flag",
	}

	// Test Set
	if err := store.Set(ctx, flag); err != nil {
		t.Fatalf("Failed to set flag: %v", err)
	}

	// Test Get
	retrieved, err := store.Get(ctx, "test-flag")
	if err != nil {
		t.Fatalf("Failed to get flag: %v", err)
	}
	if retrieved.Name != flag.Name {
		t.Errorf("Expected name %s, got %s", flag.Name, retrieved.Name)
	}
	if retrieved.Enabled != flag.Enabled {
		t.Errorf("Expected enabled %v, got %v", flag.Enabled, retrieved.Enabled)
	}

	// Test List
	flags, err := store.List(ctx)
	if err != nil {
		t.Fatalf("Failed to list flags: %v", err)
	}
	if len(flags) != 1 {
		t.Errorf("Expected 1 flag, got %d", len(flags))
	}

	// Test Delete
	if err := store.Delete(ctx, "test-flag"); err != nil {
		t.Fatalf("Failed to delete flag: %v", err)
	}

	// Verify deletion
	_, err = store.Get(ctx, "test-flag")
	if err != ErrFlagNotFound {
		t.Errorf("Expected ErrFlagNotFound, got %v", err)
	}
}

func TestService_IsEnabled(t *testing.T) {
	ctx := context.Background()
	service := NewService(StorageMemory, nil, zap.NewNop(), nil)

	// Create a flag with 50% rollout
	config := &FlagConfig{
		Enabled:     true,
		Percentage:  50,
		Description: "Test flag",
	}
	if err := service.SetFlag(ctx, "test-flag", config, "test-user"); err != nil {
		t.Fatalf("Failed to set flag: %v", err)
	}

	// Test with whitelisted user
	config.UserWhitelist = []string{"whitelisted-user"}
	if err := service.SetFlag(ctx, "test-flag", config, "test-user"); err != nil {
		t.Fatalf("Failed to update flag: %v", err)
	}

	if !service.IsEnabled(ctx, "test-flag", "whitelisted-user") {
		t.Error("Whitelisted user should have flag enabled")
	}

	// Test with blacklisted user
	config.UserWhitelist = nil
	config.UserBlacklist = []string{"blacklisted-user"}
	if err := service.SetFlag(ctx, "test-flag", config, "test-user"); err != nil {
		t.Fatalf("Failed to update flag: %v", err)
	}

	if service.IsEnabled(ctx, "test-flag", "blacklisted-user") {
		t.Error("Blacklisted user should have flag disabled")
	}

	// Test with disabled flag
	config.Enabled = false
	config.UserBlacklist = nil
	if err := service.SetFlag(ctx, "test-flag", config, "test-user"); err != nil {
		t.Fatalf("Failed to update flag: %v", err)
	}

	if service.IsEnabled(ctx, "test-flag", "any-user") {
		t.Error("Disabled flag should not be enabled for any user")
	}
}

func TestService_IsEnabledForPercentage(t *testing.T) {
	ctx := context.Background()
	service := NewService(StorageMemory, nil, zap.NewNop(), nil)

	// Create flags with different percentages
	testCases := []struct {
		name     string
		flag     string
		userID   string
		enabled  bool
	}{
		{"0 percent should be disabled", "0pct-flag", "user1", false},
		{"100 percent should be enabled", "100pct-flag", "user1", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var percentage int
			if tc.flag == "0pct-flag" {
				percentage = 0
			} else if tc.flag == "100pct-flag" {
				percentage = 100
			}

			config := &FlagConfig{
				Enabled:     true,
				Percentage:  percentage,
				Description: "Test flag",
			}
			if err := service.SetFlag(ctx, tc.flag, config, "test-user"); err != nil {
				t.Fatalf("Failed to set flag: %v", err)
			}

			result := service.IsEnabledForPercentage(ctx, tc.flag, tc.userID)
			if result != tc.enabled {
				t.Errorf("Expected %v for %s, got %v", tc.enabled, tc.flag, result)
			}
		})
	}
}

func TestService_ACVariants(t *testing.T) {
	ctx := context.Background()
	service := NewService(StorageMemory, nil, zap.NewNop(), nil)

	// Create flag with A/B test variants
	config := &FlagConfig{
		Enabled:     true,
		Percentage:  100,
		Description: "A/B test flag",
		Variants: []Variant{
			{Name: "control", Percentage: 50, Description: "Control group"},
			{Name: "treatment", Percentage: 50, Description: "Treatment group"},
		},
	}

	if err := service.SetFlag(ctx, "ab-test", config, "test-user"); err != nil {
		t.Fatalf("Failed to set flag: %v", err)
	}

	// Test variant assignment
	variant1, err := service.GetVariant(ctx, "ab-test", "user1")
	if err != nil {
		t.Fatalf("Failed to get variant: %v", err)
	}

	variant2, err := service.GetVariant(ctx, "ab-test", "user1")
	if err != nil {
		t.Fatalf("Failed to get variant: %v", err)
	}

	// Same user should get same variant
	if variant1 != variant2 {
		t.Errorf("Same user should get same variant, got %s and %s", variant1, variant2)
	}

	// Test setting explicit user variant
	if err := service.SetUserVariant(ctx, "ab-test", "user2", "control", "admin"); err != nil {
		t.Fatalf("Failed to set user variant: %v", err)
	}

	variant, err := service.GetVariant(ctx, "ab-test", "user2")
	if err != nil {
		t.Fatalf("Failed to get variant: %v", err)
	}

	if variant != "control" {
		t.Errorf("Expected variant 'control', got '%s'", variant)
	}

	// Test getting variant config
	controlConfig, err := service.GetVariantConfig(ctx, "ab-test", "control")
	if err != nil {
		t.Fatalf("Failed to get variant config: %v", err)
	}

	if controlConfig["description"] != "Control group" {
		t.Errorf("Expected description 'Control group', got '%v'", controlConfig["description"])
	}
}

func TestService_ValidateFlag(t *testing.T) {
	service := NewService(StorageMemory, nil, zap.NewNop(), nil)

	testCases := []struct {
		name    string
		flag    *Flag
		wantErr bool
	}{
		{
			name: "valid flag",
			flag: &Flag{Name: "valid", Enabled: true, Percentage: 50},
			wantErr: false,
		},
		{
			name: "empty name",
			flag: &Flag{Name: "", Enabled: true},
			wantErr: true,
		},
		{
			name: "percentage too high",
			flag: &Flag{Name: "test", Enabled: true, Percentage: 150},
			wantErr: true,
		},
		{
			name: "percentage negative",
			flag: &Flag{Name: "test", Enabled: true, Percentage: -10},
			wantErr: true,
		},
		{
			name: "invalid variant percentage",
			flag: &Flag{
				Name: "test",
				Enabled: true,
				Variants: []Variant{
					{Name: "control", Percentage: 60},
					{Name: "treatment", Percentage: 60},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := service.validateFlag(tc.flag)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateFlag() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestService_InitializeDefaultFlags(t *testing.T) {
	ctx := context.Background()
	service := NewService(StorageMemory, nil, zap.NewNop(), nil)

	if err := service.InitializeDefaultFlags(ctx); err != nil {
		t.Fatalf("Failed to initialize default flags: %v", err)
	}

	// Verify all default flags exist
	defaultFlags := []string{"new-auth-flow", "enhanced-mfa", "beta-dashboard"}
	for _, flagName := range defaultFlags {
		flag, err := service.GetFlagConfig(ctx, flagName)
		if err != nil {
			t.Errorf("Default flag %s not found: %v", flagName, err)
		}
		if flag == nil {
			t.Errorf("Default flag %s is nil", flagName)
		}
	}

	// Running again should not error (flags already exist)
	if err := service.InitializeDefaultFlags(ctx); err != nil {
		t.Errorf("Re-initializing default flags should not error: %v", err)
	}
}

func TestService_GetMetrics(t *testing.T) {
	ctx := context.Background()
	service := NewService(StorageMemory, nil, zap.NewNop(), nil)

	// Create some test flags
	flags := map[string]*FlagConfig{
		"flag1": {Enabled: true, Percentage: 100, Description: "Flag 1"},
		"flag2": {Enabled: false, Percentage: 0, Description: "Flag 2"},
		"flag3": {Enabled: true, Percentage: 50, Description: "Flag 3"},
	}

	for name, config := range flags {
		if err := service.SetFlag(ctx, name, config, "test"); err != nil {
			t.Fatalf("Failed to set flag %s: %v", name, err)
		}
	}

	metrics, err := service.GetMetrics(ctx)
	if err != nil {
		t.Fatalf("Failed to get metrics: %v", err)
	}

	if metrics["total_flags"].(int) != 3 {
		t.Errorf("Expected total_flags=3, got %v", metrics["total_flags"])
	}
	if metrics["enabled_flags"].(int) != 2 {
		t.Errorf("Expected enabled_flags=2, got %v", metrics["enabled_flags"])
	}
	if metrics["disabled_flags"].(int) != 1 {
		t.Errorf("Expected disabled_flags=1, got %v", metrics["disabled_flags"])
	}
}

func TestService_FlagChangeAuditing(t *testing.T) {
	ctx := context.Background()

	// Mock audit logger
	var capturedChange *FlagChange
	mockAudit := &mockAuditLogger{
		logFunc: func(change *FlagChange) {
			capturedChange = change
		},
	}

	service := NewService(StorageMemory, nil, zap.NewNop(), mockAudit)

	// Create a flag
	config := &FlagConfig{
		Enabled:     true,
		Percentage:  50,
		Description: "Test flag",
	}
	if err := service.SetFlag(ctx, "audit-test", config, "admin-user"); err != nil {
		t.Fatalf("Failed to set flag: %v", err)
	}

	if capturedChange == nil {
		t.Fatal("Audit log was not called")
	}

	if capturedChange.Action != "created" {
		t.Errorf("Expected action 'created', got '%s'", capturedChange.Action)
	}
	if capturedChange.Actor != "admin-user" {
		t.Errorf("Expected actor 'admin-user', got '%s'", capturedChange.Actor)
	}

	// Update the flag
	capturedChange = nil
	config.Enabled = false
	if err := service.SetFlag(ctx, "audit-test", config, "admin-user"); err != nil {
		t.Fatalf("Failed to update flag: %v", err)
	}

	if capturedChange == nil {
		t.Fatal("Audit log was not called for update")
	}
	if capturedChange.Action != "updated" {
		t.Errorf("Expected action 'updated', got '%s'", capturedChange.Action)
	}
}

func TestGetUserPercentage(t *testing.T) {
	service := NewService(StorageMemory, nil, zap.NewNop(), nil)

	// Test that the same user gets the same percentage
	p1 := service.getUserPercentage("user1", "flag1")
	p2 := service.getUserPercentage("user1", "flag1")

	if p1 != p2 {
		t.Errorf("Same user should get same percentage, got %d and %d", p1, p2)
	}

	// Test that different users get different percentages (likely)
	p3 := service.getUserPercentage("user2", "flag1")
	// They might be the same by chance, but very unlikely
	if p1 == p2 && p2 == p3 {
		t.Log("All users got same percentage (unlikely but possible)")
	}

	// Test that percentage is always 0-99
	for i := 0; i < 100; i++ {
		userID := fmt.Sprintf("user%d", i)
		p := service.getUserPercentage(userID, "flag1")
		if p < 0 || p > 99 {
			t.Errorf("Percentage %d out of range for user %s", p, userID)
		}
	}
}

// mockAuditLogger is a test implementation of AuditLogger
type mockAuditLogger struct {
	logFunc func(change *FlagChange)
}

func (m *mockAuditLogger) LogFeatureFlagChange(change *FlagChange) {
	if m.logFunc != nil {
		m.logFunc(change)
	}
}
