package identity

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ProviderType defines the type of the identity provider.
type ProviderType string

const (
	// ProviderTypeOIDC represents an OpenID Connect provider.
	ProviderTypeOIDC ProviderType = "oidc"
	// ProviderTypeSAML represents a SAML 2.0 provider.
	ProviderTypeSAML ProviderType = "saml"
)

// Scopes is a custom type for a slice of strings to be stored as JSON.
type Scopes []string

// Value implements the driver.Valuer interface.
func (s Scopes) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements the sql.Scanner interface.
func (s *Scopes) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return json.Unmarshal(value.([]byte), s)
	}
}

// IdentityProvider represents an external identity provider configuration.
type IdentityProvider struct {
	ID           uuid.UUID    `json:"id" db:"id"`
	Name         string       `json:"name" db:"name"`
	ProviderType ProviderType `json:"provider_type" db:"provider_type"`
	IssuerURL    string       `json:"issuer_url" db:"issuer_url"`
	ClientID     string       `json:"client_id" db:"client_id"`
	ClientSecret string       `json:"-" db:"client_secret"`
	Scopes       Scopes       `json:"scopes" db:"scopes"`
	Enabled      bool         `json:"enabled" db:"enabled"`
	CreatedAt    time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at" db:"updated_at"`
}
