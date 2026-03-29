# oauth

`import "github.com/openidx/openidx/internal/oauth"`

Package oauth provides an OAuth 2.0 / OpenID Connect provider with PKCE support, RSA key management, SAML integration, and social login. Runs as the OAuth Service on port **8006**.

## Service

```go
type Service struct { /* unexported fields */ }

func NewService(db *database.PostgresDB, redis *database.RedisClient, identitySvc *identity.Service, cfg *config.Config, logger *zap.Logger) *Service
func (s *Service) RegisterRoutes(r *gin.Engine)
```

## OAuth Client

```go
type OAuthClient struct {
    ID, ClientID, ClientSecret, Name, Description, Type string  // Type: "confidential" or "public"
    RedirectURIs, GrantTypes, ResponseTypes, Scopes []string
    PKCERequired bool; AllowRefreshToken bool
    AccessTokenLifetime, RefreshTokenLifetime int  // seconds
}
```

## Token Types

```go
type AuthorizationCode struct {
    Code, ClientID, UserID, RedirectURI, Scope, State, Nonce string
    CodeChallenge, CodeChallengeMethod string  // PKCE fields
    ExpiresAt time.Time
}
type AccessToken struct { Token, ClientID, UserID, Scope string; ExpiresAt time.Time }
type RefreshToken struct { Token, ClientID, UserID, Scope, SessionID string; ExpiresAt time.Time }
type TokenResponse struct { AccessToken, TokenType string; ExpiresIn int; RefreshToken, IDToken, Scope string }
```

## Key Management

```go
const KeySize = 3072                          // RSA key size in bits (NIST recommendation through 2030)
const KeyLifetime = 90 * 24 * time.Hour       // 90 days
const KeyRotationOverlap = 24 * time.Hour     // Overlap period for graceful rotation

type KeyMetadata struct { KeyID, KeyType, Algorithm, Use, PublicKey string }

var ErrKeyGenerationFailed, ErrKeyNotFound, ErrKeyInvalid, ErrKeyRotationInProgress error
```

## OpenID Connect Discovery

```go
type DiscoveryDocument struct {
    Issuer, AuthorizationEndpoint, TokenEndpoint, JWKSURI string
    ResponseTypesSupported, SubjectTypesSupported []string
    IDTokenSigningAlgValuesSupported []string
    ScopesSupported, GrantTypesSupported, ClaimsSupported []string
    CodeChallengeMethodsSupported []string
    EndSessionEndpoint, RevocationEndpoint, IntrospectionEndpoint string
}
```

The discovery document is served at `/.well-known/openid-configuration`. JWKS is available at `/.well-known/jwks.json`.
