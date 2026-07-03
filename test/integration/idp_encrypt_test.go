//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"github.com/openidx/openidx/internal/identity"
)

// TestIDPClientSecretEncryptedAtRest proves the external-IdP OIDC client secret is
// encrypted at rest: CreateIdentityProvider stores ciphertext (tagged encv1:, never
// plaintext) and GetIdentityProvider decrypts it back. Runs on the real test DB
// (bypass-RLS + a seeded org) with a miniredis; requires migration v66 (TEXT).
func TestIDPClientSecretEncryptedAtRest(t *testing.T) {
	db, err := database.NewPostgres(integrationDSN(t))
	require.NoError(t, err, "connect test DB")
	defer db.Close()
	ctx := context.Background()

	mini, err := miniredis.Run()
	require.NoError(t, err)
	defer mini.Close()
	rc := &database.RedisClient{Client: redis.NewClient(&redis.Options{Addr: mini.Addr()})}

	cfg := &config.Config{EncryptionKey: "0123456789abcdef0123456789abcdef"}
	svc := identity.NewService(db, rc, cfg, zaptest.NewLogger(t))

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	orgID := seedOrg(t, db.Pool, "idp-enc-"+suffix)
	t.Cleanup(func() { bypassExec(t, db.Pool, "DELETE FROM organizations WHERE id=$1", orgID) })
	octx := orgctx.With(orgctx.WithBypassRLS(ctx), orgctx.Org{ID: orgID})

	const plaintext = "idp_secret_ABC123_recoverable"
	idp := &identity.IdentityProvider{
		Name:         "enc-" + suffix,
		ProviderType: identity.ProviderTypeOIDC,
		IssuerURL:    "https://idp.example.test",
		ClientID:     "cid-" + suffix,
		ClientSecret: plaintext,
		Scopes:       identity.Scopes{"openid"},
		Enabled:      true,
	}
	require.NoError(t, svc.CreateIdentityProvider(octx, idp))
	t.Cleanup(func() { bypassExec(t, db.Pool, "DELETE FROM identity_providers WHERE id=$1", idp.ID) })

	// At rest the column holds tagged ciphertext, never the plaintext.
	var stored string
	require.NoError(t, db.Pool.QueryRow(octx,
		"SELECT client_secret FROM identity_providers WHERE id=$1", idp.ID).Scan(&stored))
	assert.True(t, secretcrypt.IsEncrypted(stored), "IdP client_secret must be encrypted (encv1: tag)")
	assert.NotContains(t, stored, plaintext)

	// Read decrypts back to the plaintext (needed for outbound OIDC exchange).
	got, err := svc.GetIdentityProvider(octx, idp.ID.String())
	require.NoError(t, err)
	assert.Equal(t, plaintext, got.ClientSecret)
}
