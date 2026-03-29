// Package identity provides benchmark tests for identity service
package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// createTestServiceForBench creates a test service for benchmarking
func createTestServiceForBench(tb testing.TB) *Service {
	tb.Helper()

	cfg := &config.Config{
		DatabaseURL: "postgres://localhost:5432/openidx_test?sslmode=disable",
	}

	logger := zap.NewNop()

	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		tb.Skip("Skipping benchmark: database not available")
	}

	redisClient, err := database.NewRedis("redis://localhost:6379")
	if err != nil {
		tb.Skip("Skipping benchmark: redis not available")
	}

	svc := NewService(db, redisClient, cfg, logger)

	// Set minimal webhook publisher
	svc.SetWebhookService(&mockWebhookPublisherForBench{})
	svc.SetAnomalyDetector(&mockAnomalyDetectorForBench{})

	return svc
}

// mockWebhookPublisherForBench is a minimal mock for benchmarking
type mockWebhookPublisherForBench struct{}

func (m *mockWebhookPublisherForBench) Publish(ctx context.Context, eventType string, payload interface{}) error {
	return nil
}

// mockAnomalyDetectorForBench is a minimal mock for benchmarking
type mockAnomalyDetectorForBench struct{}

func (m *mockAnomalyDetectorForBench) RunAnomalyCheck(ctx context.Context, userID, ip, userAgent string, lat, lon float64) interface{} {
	return nil
}

func (m *mockAnomalyDetectorForBench) CheckIPThreatList(ctx context.Context, ip string) (bool, string) {
	return false, ""
}

// BenchmarkAuthenticate benchmarks user authentication performance
func BenchmarkAuthenticate(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test user with known credentials
	username := "bench_user_" + randomString(8)
	password := "BenchmarkPassword123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	now := time.Now()
	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
		ON CONFLICT (username) DO UPDATE SET password_hash = $4
	`, username+"-id", username, username+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	// Clean up after benchmark
	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE username = $1", username)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.AuthenticateUser(ctx, username, password)
	}
}

// BenchmarkGetUserByID benchmarks retrieving a single user by ID
func BenchmarkGetUserByID(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test user
	userID := "bench_user_get_" + randomString(8)
	username := "bench_get_user_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)

	now := time.Now()
	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, username, username+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.GetUser(ctx, userID)
	}
}

// BenchmarkListUsersPaginated benchmarks listing users with pagination
func BenchmarkListUsersPaginated(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test users
	const testUserCount = 100
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	for i := 0; i < testUserCount; i++ {
		username := "bench_list_user_" + randomString(8)
		_, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
			VALUES ($1, $2, $3, $4, true, true, $5, $5)
			ON CONFLICT (username) DO NOTHING
		`, username+"-id", username, username+"@example.com", hashedPassword, now)
		if err != nil {
			b.Fatalf("Failed to create test users: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.ListUsers(ctx, 0, 20)
	}
}

// BenchmarkListUsersWithSearch benchmarks listing users with search filter
func BenchmarkListUsersWithSearch(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test users with predictable names
	const testUserCount = 100
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	for i := 0; i < testUserCount; i++ {
		username := "search_test_user_" + randomString(8)
		_, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
			VALUES ($1, $2, $3, $4, true, true, $5, $5)
			ON CONFLICT (username) DO NOTHING
		`, username+"-id", username, username+"@example.com", hashedPassword, now)
		if err != nil {
			b.Fatalf("Failed to create test users: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.ListUsers(ctx, 0, 20, "search_test")
	}
}

// BenchmarkCreateSession benchmarks creating a user session
func BenchmarkCreateSession(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test user
	userID := "bench_session_user_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, userID, userID+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		svc.db.Pool.Exec(ctx, "DELETE FROM user_sessions WHERE user_id = $1", userID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.CreateSession(ctx, userID, "test-client", "127.0.0.1", "test-agent", 24*time.Hour)
	}
}

// BenchmarkIsSessionValid benchmarks session validation
func BenchmarkIsSessionValid(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test user and session
	userID := "bench_valid_session_user_" + randomString(8)
	sessionID := "bench_session_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, userID, userID+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	_, err = svc.db.Pool.Exec(ctx, `
		INSERT INTO user_sessions (id, user_id, client_id, ip_address, user_agent, started_at, last_seen_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
	`, sessionID, userID, "test-client", "127.0.0.1", "test-agent", now, now.Add(24*time.Hour))
	if err != nil {
		b.Fatalf("Failed to create test session: %v", err)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		svc.db.Pool.Exec(ctx, "DELETE FROM user_sessions WHERE id = $1", sessionID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.IsSessionValid(ctx, sessionID)
	}
}

// BenchmarkGetUserRoles benchmarks fetching user roles
func BenchmarkGetUserRoles(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test user with roles
	userID := "bench_roles_user_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, userID, userID+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	// Create roles and assign them
	const roleCount = 10
	for i := 0; i < roleCount; i++ {
		roleID := "bench_role_" + randomString(8)
		_, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO roles (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (name) DO NOTHING
		`, roleID, "role_"+randomString(4), "Benchmark role", now)
		if err != nil {
			continue
		}
		_, _ = svc.db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, userID, roleID, "system", now)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1", userID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.GetUserRoles(ctx, userID)
	}
}

// BenchmarkVerifyTOTP benchmarks TOTP verification (without using authenticator)
func BenchmarkVerifyTOTP(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test user with TOTP
	userID := "bench_totp_user_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	secret := generateBase32Secret(16)
	now := time.Now()

	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, userID, userID+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	_, err = svc.db.Pool.Exec(ctx, `
		INSERT INTO mfa_totp (id, user_id, secret, enabled, enrolled_at, created_at, updated_at)
		VALUES ($1, $2, $3, true, $4, $4, $4)
	`, userID+"-totp", userID, secret, now)
	if err != nil {
		b.Fatalf("Failed to create TOTP: %v", err)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM mfa_totp WHERE user_id = $1", userID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	// Use a valid TOTP code (generated for testing - 6 digits, all zeros for benchmark speed)
	// Note: In real benchmarks, you'd generate valid codes using the secret
	testCode := "000000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.VerifyTOTP(ctx, userID, testCode)
	}
}

// BenchmarkListGroups benchmarks listing groups
func BenchmarkListGroups(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create test groups
	const groupCount = 50
	now := time.Now()

	for i := 0; i < groupCount; i++ {
		groupID := "bench_group_" + randomString(8)
		_, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO groups (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (name) DO NOTHING
		`, groupID, "group_"+randomString(4), "Benchmark group", now)
		if err != nil {
			continue
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = svc.ListGroups(ctx, 0, 20)
	}
}

// Helper functions

func randomString(n int) string {
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func generateBase32Secret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	// Base32 encode (simplified - in production use proper base32 encoding)
	return hex.EncodeToString(b)
}
