// Package identity provides benchmark tests for identity service
package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// createTestServiceForBench creates a test service for benchmarking
func createTestServiceForBench(tb testing.TB) *Service {
	tb.Helper()

	// DATABASE_URL first: the hardcoded DSN names a database (openidx_test) that
	// neither CI nor the compose stack creates, so these benchmarks skip
	// everywhere -- the benchmark job runs `go test -bench=. ./...` with no
	// Postgres service at all. Reading the variable the rest of the suite uses
	// means they exercise something when anyone runs them, rather than
	// reporting a skip that reads like a pass.
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://localhost:5432/openidx_test?sslmode=disable"
	}
	cfg := &config.Config{DatabaseURL: dsn}

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

// benchCtx is the context these benchmarks must run under. Every service method
// here resolves the tenant from the context, so a bare context.Background()
// makes each call return "orgctx: no organization context on request" before it
// touches the database -- which is what the whole file was timing. A
// BenchmarkAuthenticate that reports ~1µs/op is not measuring bcrypt.
func benchCtx() context.Context {
	return orgctx.With(context.Background(), orgctx.Org{
		ID:   "00000000-0000-0000-0000-000000000010",
		Slug: "default",
	})
}

// benchErr holds the last result of the timed call. Checking it after the loop
// is what keeps these honest: a benchmark that errors on every iteration is
// timing an error path, and it should say so rather than publish the number.
var benchErr error

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

	ctx := benchCtx()

	// Create a test user with known credentials
	username := "bench_user_" + randomString(8)
	password := "BenchmarkPassword123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	now := time.Now()
	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
		ON CONFLICT (username) DO UPDATE SET password_hash = $4
	`, uuid.NewString(), username, username+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	// Clean up after benchmark
	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE username = $1", username)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, benchErr = svc.AuthenticateUser(ctx, username, password)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.AuthenticateUser", benchErr)
	}
}

// BenchmarkGetUserByID benchmarks retrieving a single user by ID
func BenchmarkGetUserByID(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test user
	userID := uuid.NewString()
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
		_, benchErr = svc.GetUser(ctx, userID)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.GetUser", benchErr)
	}
}

// BenchmarkListUsersPaginated benchmarks listing users with pagination
func BenchmarkListUsersPaginated(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

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
		`, uuid.NewString(), username, username+"@example.com", hashedPassword, now)
		if err != nil {
			b.Fatalf("Failed to create test users: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, benchErr = svc.ListUsers(ctx, 0, 20)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.ListUsers", benchErr)
	}
}

// BenchmarkListUsersWithSearch benchmarks listing users with search filter
func BenchmarkListUsersWithSearch(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

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
		`, uuid.NewString(), username, username+"@example.com", hashedPassword, now)
		if err != nil {
			b.Fatalf("Failed to create test users: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, benchErr = svc.ListUsers(ctx, 0, 20, "search_test")
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.ListUsers", benchErr)
	}
}

// BenchmarkCreateSession benchmarks creating a user session
func BenchmarkCreateSession(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test user
	userID := uuid.NewString()
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
		_, benchErr = svc.CreateSession(ctx, userID, "test-client", "127.0.0.1", "test-agent", 24*time.Hour)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.CreateSession", benchErr)
	}
}

// BenchmarkIsSessionValid benchmarks session validation
func BenchmarkIsSessionValid(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test user and session
	userID := uuid.NewString()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, userID, userID+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	// Seed through the product's own path. The hand-written INSERT this
	// replaces put a row in user_sessions naming three columns that table has
	// never had (client_id, started_at, last_seen_at) -- and IsSessionValid
	// reads `sessions`, a different table, so even a corrected insert would
	// have timed a lookup that finds nothing. Calling CreateSession keeps the
	// benchmark pointed at whichever table the service actually uses.
	session, err := svc.CreateSession(ctx, userID, "bench-client", "127.0.0.1", "test-agent", 24*time.Hour)
	if err != nil {
		b.Fatalf("Failed to create test session: %v", err)
	}
	sessionID := session.ID

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		svc.db.Pool.Exec(ctx, "DELETE FROM user_sessions WHERE id = $1", sessionID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, benchErr = svc.IsSessionValid(ctx, sessionID)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.IsSessionValid", benchErr)
	}
}

// BenchmarkGetUserRoles benchmarks fetching user roles
func BenchmarkGetUserRoles(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test user with roles
	userID := uuid.NewString()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, userID, userID+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	// `ON CONFLICT (name)` needs a unique index on exactly (name), and roles
	// moved to (org_id, name) in v173, so this statement cannot succeed --
	// `continue` swallowed the error, and the benchmark itself has never run
	// (see the DSN note in createTestServiceForBench), which is why nothing
	// surfaced it. The names are random, so no conflict is possible and the
	// bare DO NOTHING names no index that can be re-keyed underneath it.
	// Seeding failures are fatal now: a benchmark whose premise did not land
	// should stop, not publish.
	const roleCount = 10
	for i := 0; i < roleCount; i++ {
		roleID := uuid.NewString()
		if _, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO roles (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT DO NOTHING
		`, roleID, "bench_role_"+uuid.NewString(), "Benchmark role", now); err != nil {
			b.Fatalf("seed role: %v", err)
		}
		if _, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_at)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING
		`, userID, roleID, now); err != nil {
			b.Fatalf("grant role: %v", err)
		}
	}

	var gotRoles int
	if err := svc.db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM user_roles WHERE user_id = $1", userID).Scan(&gotRoles); err != nil {
		b.Fatalf("count seeded roles: %v", err)
	}
	if gotRoles != roleCount {
		b.Fatalf("seeded %d roles, want %d — this benchmark would time a user with none", gotRoles, roleCount)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1", userID)
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, benchErr = svc.GetUserRoles(ctx, userID)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.GetUserRoles", benchErr)
	}
}

// BenchmarkVerifyTOTP benchmarks TOTP verification (without using authenticator)
func BenchmarkVerifyTOTP(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test user with TOTP
	userID := uuid.NewString()
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
	`, uuid.NewString(), userID, secret, now)
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
		_, benchErr = svc.VerifyTOTP(ctx, userID, testCode)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.VerifyTOTP", benchErr)
	}
}

// BenchmarkListGroups benchmarks listing groups
func BenchmarkListGroups(b *testing.B) {
	svc := createTestServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Same as the roles seeding above: groups has been keyed (org_id, name) for
	// some time, so `ON CONFLICT (name)` cannot succeed here either and
	// `continue` hid it. Left as it was, BenchmarkListGroups would list
	// whatever the database already held rather than the 50 it says it creates.
	const groupCount = 50
	now := time.Now()

	for i := 0; i < groupCount; i++ {
		groupID := uuid.NewString()
		if _, err := svc.db.Pool.Exec(ctx, `
			INSERT INTO groups (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT DO NOTHING
		`, groupID, "bench_group_"+uuid.NewString(), "Benchmark group", now); err != nil {
			b.Fatalf("seed group: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, benchErr = svc.ListGroups(ctx, 0, 20)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.ListGroups", benchErr)
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
