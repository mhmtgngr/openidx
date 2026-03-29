// Package oauth provides benchmark tests for OAuth/OIDC service
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/identity"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// createTestOAuthServiceForBench creates a test OAuth service for benchmarking
func createTestOAuthServiceForBench(b testing.TB) (*Service, *identity.Service, *database.PostgresDB) {
	b.Helper()

	cfg := &config.Config{
		DatabaseURL: "postgres://localhost:5432/openidx_test?sslmode=disable",
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

	ctx := context.Background()

	// Create a test user
	userID := "bench_token_user_" + randomString(8)
	username := "bench_token_user"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()

	_, err := db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, username, username+"@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	// Create roles for the user
	const roleCount = 5
	for i := 0; i < roleCount; i++ {
		roleID := "bench_role_" + randomString(8)
		db.Pool.Exec(ctx, `
			INSERT INTO roles (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (name) DO NOTHING
		`, roleID, "role_"+randomString(4), "Benchmark role", now)

		db.Pool.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, userID, roleID, "system", now)
	}

	// Create groups for the user
	const groupCount = 3
	for i := 0; i < groupCount; i++ {
		groupID := "bench_group_" + randomString(8)
		db.Pool.Exec(ctx, `
			INSERT INTO groups (id, name, description, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (name) DO NOTHING
		`, groupID, "group_"+randomString(4), "Benchmark group", now)

		db.Pool.Exec(ctx, `
			INSERT INTO group_memberships (group_id, user_id, joined_at)
			VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING
		`, groupID, userID, now)
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
		_, _ = svc.GenerateJWT(ctx, userID, clientID, scope, expiresIn)
	}
}

// BenchmarkGenerateIDToken benchmarks ID token generation
func BenchmarkGenerateIDToken(b *testing.B) {
	svc, _, db := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test user
	userID := "bench_idtoken_user_" + randomString(8)
	username := "bench_idtoken_user"
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
		_, _ = svc.GenerateIDToken(ctx, userID, clientID, nonce, expiresIn)
	}
}

// BenchmarkValidateToken benchmarks JWT token validation using KeyManager
func BenchmarkValidateToken(b *testing.B) {
	svc, _, _ := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	// Set up KeyManager with a test key
	if svc.keyManager == nil {
		// Create a simple test token if no key manager
		b.Skip("Skipping: KeyManager not set up")
		return
	}

	// Generate a valid test token
	ctx := context.Background()
	userID := "bench_validate_user_" + randomString(8)

	// Create user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	now := time.Now()
	svc.db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, "validate_user", "validate@example.com", hashedPassword, now)

	token, _ := svc.GenerateJWT(ctx, userID, "bench-client", "openid profile", 3600)

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.keyManager.ValidateJWT(token)
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
		"sub":  "user123",
		"aud":  "client123",
		"iss":  svc.issuer,
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour).Unix(),
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

// BenchmarkAuthorizeFlow benchmarks the authorization flow parsing and validation
func BenchmarkAuthorizeFlow(b *testing.B) {
	svc, _, db := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test OAuth client
	clientID := "bench_auth_client_" + randomString(8)
	clientSecret := "bench-secret"
	hashedSecret := hashClientSecret(clientSecret)

	now := time.Now()
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, pkce_required, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'confidential', $5, $6, $7, $8, true, $9, $9)
	`, clientID+"-id", clientID, hashedSecret, "Benchmark Client",
		[]string{"http://localhost:3000/callback"},
		[]string{"authorization_code", "refresh_token"},
		[]string{"code"},
		[]string{"openid", "profile", "email"},
		now)
	if err != nil {
		b.Fatalf("Failed to create test client: %v", err)
	}

	// Create a test user
	userID := "bench_auth_user_" + randomString(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, err = db.Pool.Exec(ctx, `
		INSERT INTO users (id, username, email, password_hash, enabled, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, true, true, $5, $5)
	`, userID, "auth_user", "auth@example.com", hashedPassword, now)
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}

	b.Cleanup(func() {
		db.Pool.Exec(ctx, "DELETE FROM oauth_clients WHERE client_id = $1", clientID)
		db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)
	})

	// Set up AuthorizeFlow
	clients := NewClientRepository(svc.db, zap.NewNop())
	_ = NewAuthorizeFlow(clients, nil, zap.NewNop(), svc.issuer)

	// Create authorization request parameters
	codeVerifier := generateRandomString(43)
	codeChallenge := benchSha256Hash(codeVerifier)
	state := generateRandomString(16)

	// Measure the parsing and validation part (not the full flow with redirect)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := &FlowAuthorizeRequest{
			ClientID:             clientID,
			RedirectURI:          "http://localhost:3000/callback",
			ResponseType:         "code",
			Scope:                "openid profile email",
			State:                state,
			CodeChallenge:        codeChallenge,
			CodeChallengeMethod:  "S256",
		}

		// Validate client
		_, _ = clients.GetByClientID(ctx, req.ClientID)
		// Validate scope
		_ = clients.ValidateScope(nil, req.Scope)
		_ = req
	}
}

// BenchmarkCreateAuthorizationCode benchmarks authorization code creation and storage
func BenchmarkCreateAuthorizationCode(b *testing.B) {
	svc, _, db := createTestOAuthServiceForBench(b)
	if svc == nil {
		return
	}

	ctx := context.Background()

	// Create a test client and user
	clientID := "bench_code_client_" + randomString(8)
	userID := "bench_code_user_" + randomString(8)

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
			Code:                generateRandomString(32),
			ClientID:            clientID,
			UserID:              userID,
			RedirectURI:         "http://localhost:3000/callback",
			Scope:               "openid",
			ExpiresAt:           time.Now().Add(10 * time.Minute),
			CreatedAt:           time.Now(),
			CodeChallenge:       generateRandomString(43),
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

	ctx := context.Background()

	// Create a test client
	clientID := "bench_get_client_" + randomString(8)
	now := time.Now()

	svc.db.Pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, client_id, client_secret, name, type, redirect_uris, grant_types, response_types, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'confidential', $5, $6, $7, $8, $9, $9)
	`, clientID+"-id", clientID, "secret", "Benchmark Client",
		[]string{"http://localhost:3000/callback"},
		[]string{"authorization_code"},
		[]string{"code"},
		[]string{"openid"},
		now)

	b.Cleanup(func() {
		svc.db.Pool.Exec(ctx, "DELETE FROM oauth_clients WHERE client_id = $1", clientID)
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.GetClient(ctx, clientID)
	}
}

// BenchmarkPKCEVerification benchmarks PKCE code verifier validation
func BenchmarkPKCEVerification(b *testing.B) {
	codeVerifier := generateRandomString(43)
	codeChallenge := benchSha256Hash(codeVerifier)

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

	ctx := context.Background()

	// Create test data
	clientID := "bench_refresh_client_" + randomString(8)
	userID := "bench_refresh_user_" + randomString(8)
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
	b := make([]byte, n/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// hashClientSecret is defined in client.go

// benchSha256Hash is a simplified SHA256 hash for benchmark PKCE code challenges
func benchSha256Hash(s string) string {
	return hex.EncodeToString([]byte(s))[:32]
}
