// Package oauth provides benchmark tests for OAuth/OIDC service
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/identity"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// createTestOAuthServiceForBench creates a test OAuth service for benchmarking
func createTestOAuthServiceForBench(b testing.TB) (*Service, *identity.Service, *database.PostgresDB) {
	b.Helper()

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
	cfg := &config.Config{
		DatabaseURL: dsn,
		OAuthIssuer: "http://localhost:8006",
	}

	logger := zap.NewNop()

	db, err := database.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		b.Skip("Skipping benchmark: database not available")
	}

	redis, err := database.NewRedis("redis://localhost:6379")
	if err != nil {
		b.Skip("Skipping benchmark: redis not available")
	}

	idSvc := identity.NewService(db, redis, cfg, logger)

	svc, err := NewService(db, redis, cfg, logger, idSvc)
	if err != nil {
		b.Fatalf("Failed to create OAuth service: %v", err)
	}

	// Generate and set a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("Failed to generate RSA key: %v", err)
	}
	svc.privateKey = privateKey
	svc.publicKey = &privateKey.PublicKey

	svc.SetWebhookService(&mockOAuthWebhookPublisherForBench{})

	return svc, idSvc, db
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

// mockOAuthWebhookPublisherForBench is a minimal mock for benchmarking
type mockOAuthWebhookPublisherForBench struct{}

func (m *mockOAuthWebhookPublisherForBench) Publish(ctx context.Context, eventType string, payload interface{}) error {
	return nil
}

// BenchmarkGenerateToken benchmarks JWT access token generation
func BenchmarkGenerateToken(b *testing.B) {
	svc, _, db := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test user
	userID := uuid.NewString()
	username := "bench_token_user_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, username, username+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	// Both name-keyed inserts named a conflict target that does not exist:
	// `ON CONFLICT (name)` needs a unique index on exactly (name), groups has
	// been keyed (org_id, name) for some time, and roles moved to (org_id, name)
	// in v173. Neither statement can succeed.
	//
	// Nobody noticed because these Execs dropped their errors AND the benchmark
	// has never run: the DSN above named a database nothing creates, so it
	// skipped everywhere, and the benchmark job has no Postgres service at all.
	// Reading DATABASE_URL is what made it run, and running it is what turned
	// the broken seeding up.
	//
	// The names are random, so no conflict is possible; the bare DO NOTHING
	// keeps the belt without naming an index that can be re-keyed underneath it.
	// Seeding failures are fatal now — a benchmark whose premise did not land
	// should stop rather than publish a number for the wrong thing.
	const roleCount = 5
	for i := 0; i < roleCount; i++ {
		roleID := uuid.NewString()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO roles (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT DO NOTHING
		`, roleID, "bench_role_"+uuid.NewString(), "Benchmark role", now); err != nil {
			b.Fatalf("seed role: %v", err)
		}

		// assigned_by is a uuid column; "system" is not one, so this insert has
		// never succeeded. Left NULL: nobody assigned it.
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_at)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING
		`, userID, roleID, now); err != nil {
			b.Fatalf("grant role: %v", err)
		}
	}

	const groupCount = 3
	for i := 0; i < groupCount; i++ {
		groupID := uuid.NewString()
		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO groups (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT DO NOTHING
		`, groupID, "bench_group_"+uuid.NewString(), "Benchmark group", now); err != nil {
			b.Fatalf("seed group: %v", err)
		}

		if _, err := db.Pool.Exec(ctx, `
			INSERT INTO group_memberships (group_id, user_id, joined_at)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING
		`, groupID, userID, now); err != nil {
			b.Fatalf("add group membership: %v", err)
		}
	}

	// The seeding is the benchmark's premise, so check it landed rather than
	// trusting that four inserts with no error means four rows.
	var gotRoles, gotGroups int
	if err := db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM user_roles WHERE user_id = $1", userID).Scan(&gotRoles); err != nil {
		b.Fatalf("count seeded roles: %v", err)
	}
	if err := db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM group_memberships WHERE user_id = $1", userID).Scan(&gotGroups); err != nil {
		b.Fatalf("count seeded groups: %v", err)
	}
	if gotRoles != roleCount || gotGroups != groupCount {
		b.Fatalf("seeded %d roles and %d groups, want %d and %d — the benchmark would measure a different user than it claims",
			gotRoles, gotGroups, roleCount, groupCount)
	}

	b.Cleanup(func() {
		db.Pool.Exec(ctx, "DELETE FROM user_roles WHERE user_id = $1", userID)
		db.Pool.Exec(ctx, "DELETE FROM group_memberships WHERE user_id = $1", userID)
		db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	clientID := "bench-client"
	scope := "openid profile email"
	expiresIn := 3600

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, benchErr = svc.GenerateJWT(ctx, userID, clientID, scope, expiresIn)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.GenerateJWT", benchErr)
	}
}

// BenchmarkGenerateIDToken benchmarks ID token generation
func BenchmarkGenerateIDToken(b *testing.B) {
	svc, _, db := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test user
	userID := uuid.NewString()
	username := "bench_idtoken_user_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, first_name, last_name, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, true, true, $7, $7)
	`, userID, username, username+"@example.com", "Benchmark", "User", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	b.Cleanup(func() {
		db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	clientID := "bench-client"
	nonce := "bench-nonce-" + randomString(16)
	expiresIn := 3600

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, benchErr = svc.GenerateIDToken(ctx, userID, clientID, nonce, expiresIn)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.GenerateIDToken", benchErr)
	}
}

// BenchmarkValidateTokenSimple benchmarks simple JWT parsing and validation
func BenchmarkValidateTokenSimple(b *testing.B) {
	svc, _, _ := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	// Create a simple JWT for testing
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   "user123",
		"aud":   "client123",
		"iss":   svc.issuer,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"email": "test@example.com",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(svc.privateKey)
	if err != nil {
		b.Fatalf("Failed to create test token: %v", err)
	}

	// Parse with public key
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return svc.publicKey, nil
		})
		_ = parsed
		_ = err
	}
}

// BenchmarkCreateAuthorizationCode benchmarks authorization code creation and storage
func BenchmarkCreateAuthorizationCode(b *testing.B) {
	svc, _, db := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test client and user
	clientID := "bench_code_client_" + randomString(8)
	userID := uuid.NewString()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'confidential', $5, $6, $7, $8, $9, $9)
	`, clientID+"-id", clientID, "secret", "Benchmark Client",
		[]string{"http://localhost:3000/callback"},
		[]string{"authorization_code"},
		[]string{"code"},
		[]string{"openid"},
		now)

	db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, "code_user", "code@example.com", hashedPassword, now)

	b.Cleanup(func() {
		db.Pool.Exec(ctx, "DELETE FROM oauth_clients WHERE client_id = $1", clientID)
		db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		db.Pool.Exec(ctx, "DELETE FROM oauth_authorization_codes WHERE client_id = $1", clientID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		code := &AuthorizationCode{
			Code:                randomString(32),
			ClientID:            clientID,
			UserID:              userID,
			RedirectURI:         "http://localhost:3000/callback",
			Scope:               "openid",
			ExpiresAt:           time.Now().Add(10 * time.Minute),
			CreatedAt:           time.Now(),
			CodeChallenge:       randomString(43),
			CodeChallengeMethod: "S256",
		}
		_ = svc.CreateAuthorizationCode(ctx, code)
	}
}

// BenchmarkGetClient benchmarks retrieving an OAuth client
func BenchmarkGetClient(b *testing.B) {
	svc, _, _ := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create a test client
	clientID := "bench_get_client_" + randomString(8)
	now := time.Now()

	// oauth_clients.id is a uuid, so clientID+"-id" could never insert -- and the
	// error was discarded, so GetClient below was timing "oauth client not
	// found" rather than a client lookup.
	if _, err := svc.db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'confidential', $5, $6, $7, $8, $9, $9)
	`, uuid.NewString(), clientID, "secret", "Benchmark Client",
		[]string{"http://localhost:3000/callback"},
		[]string{"authorization_code"},
		[]string{"code"},
		[]string{"openid"},
		now); err != nil {
		b.Fatalf("seed oauth client: %v", err)
	}

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM oauth_clients WHERE client_id = $1", clientID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, benchErr = svc.GetClient(ctx, clientID)
	}
	if benchErr != nil {
		b.Fatalf("%s errored on every iteration: %v", "svc.GetClient", benchErr)
	}
}

// BenchmarkPKCEVerification benchmarks PKCE code verifier validation
func BenchmarkPKCEVerification(b *testing.B) {
	codeVerifier := randomString(43)
	codeChallenge := benchPKCEChallenge(codeVerifier)
	if !VerifyPKCE(codeVerifier, codeChallenge, "S256") {
		b.Fatal("benchmark fixture does not verify — this would time the rejection path")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyPKCE(codeVerifier, codeChallenge, "S256")
	}
}

// BenchmarkRefreshTokenGrant benchmarks refresh token grant processing (database setup only)
func BenchmarkRefreshTokenGrant(b *testing.B) {
	svc, _, db := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := benchCtx()

	// Create test data
	clientID := "bench_refresh_client_" + randomString(8)
	userID := uuid.NewString()
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'confidential', $5, $6, $7, $8, $9, $9)
	`, clientID+"-id", clientID, "secret", "Benchmark Client",
		[]string{"http://localhost:3000/callback"},
		[]string{"authorization_code", "refresh_token"},
		[]string{"code"},
		[]string{"openid"},
		now)

	db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, "refresh_user", "refresh@example.com", hashedPassword, now)

	b.Cleanup(func() {
		db.Pool.Exec(ctx, "DELETE FROM oauth_clients WHERE client_id = $1", clientID)
		db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
		db.Pool.Exec(ctx, "DELETE FROM oauth_refresh_tokens WHERE client_id = $1", clientID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate getting a refresh token from DB
		var token string
		_ = svc.db.Pool.QueryRow(ctx, `
			SELECT token FROM oauth_refresh_tokens
			WHERE client_id = $1 AND user_id = $2 AND expires_at > NOW()
			LIMIT 1
		`, clientID, userID).Scan(&token)
		_ = token
	}
}

// Helper functions

func randomString(n int) string {
	// Round the byte count UP: n/2 bytes hex-encodes to only n-1 characters for
	// odd n, and the slice below then panics. randomString(43) — the RFC 7636
	// minimum verifier length — produced exactly that, killing every remaining
	// benchmark in this package.
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// benchPKCEChallenge derives the S256 code challenge for a verifier, the same
// way VerifyPKCE does.
//
// Its predecessor hex-encoded the verifier and truncated to 32 chars, which is
// not SHA-256 and never matched — so the benchmark was timing the rejection
// path while claiming to measure PKCE verification.
func benchPKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
}
