package oauth

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/signingkeys"
)

// THE SIGNING-KEY REFRESH LOOP WRITES FIELDS THE REQUEST PATH READS.
//
// signerRefreshLoop is recorded in the sweeps census as per-process, and that
// answer is right: every pod needs current signing keys, so gating the refresh
// behind a leader would leave eleven of twelve oauth-service replicas serving a
// stale JWKS. Auditing it for the census turned up a different problem in the
// same function.
//
// refreshSigner swaps an immutable snapshot through an atomic pointer, which is
// exactly the right shape -- and then also assigned two plain struct fields,
// s.privateKey and s.publicKey, "for any direct readers". Those readers are the
// SAML paths: signRedirectBinding, signAssertionEnveloped, samlSigningCertBase64
// and the step-up token issuer all dereference s.privateKey on a request
// goroutine, with no lock and no atomic.
//
// So an unsynchronised pointer write raced every SAML signature. It is not only
// the ticker either: verificationKeyfunc calls refreshSigner inline when a token
// carries an unknown kid, so one request signing a SAML redirect could race
// another request verifying a token.
//
// This test runs the two real functions against each other. On the code that
// assigned those fields, `go test -race` reported the write in refreshSigner
// against the read in signRedirectBinding on the first attempt -- two races,
// in fact: the pointer field, and the rsa.PrivateKey struct it pointed at.
//
// WHAT THIS TEST GUARDS, PRECISELY, because the two halves of the fix are not
// interchangeable. A race needs both the write and the unsynchronised read.
// This test covers the READ half: put the field read back into any SAML signing
// path and it goes red again. Putting only the WRITE back leaves it green --
// nothing reads the field concurrently any more -- which is why the write half
// has its own guard, TestTheLegacySigningFieldsAreWrittenOnlyAtConstruction.
// Measured both ways rather than assumed: reintroducing `s.privateKey =
// snap.priv` alone does NOT turn this test red.
func TestRefreshingTheSignerDoesNotRaceWithSAMLSigning(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set; skipping the signer refresh race test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, `
		DROP TABLE IF EXISTS oauth_signing_keys;
		CREATE TABLE oauth_signing_keys (
			kid VARCHAR(255) PRIMARY KEY,
			private_key_pem TEXT NOT NULL,
			status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'retired')),
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			activated_at TIMESTAMP WITH TIME ZONE,
			retired_at TIMESTAMP WITH TIME ZONE,
			not_after TIMESTAMP WITH TIME ZONE);
		CREATE UNIQUE INDEX uq_oauth_signing_keys_active ON oauth_signing_keys (status) WHERE status = 'active';`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS oauth_signing_keys;`) })

	store := signingkeys.NewStore(pool, "", "", zap.NewNop())
	active, err := store.EnsureActive(ctx, nil)
	require.NoError(t, err)

	// A Service with just the signing collaborators: the two functions under
	// test need the key store, the legacy key and the issuer, and nothing else.
	svc := &Service{keyStore: store, logger: zap.NewNop(), issuer: "https://idp.example.test"}
	svc.privateKey = active.Private
	svc.publicKey = &active.Private.PublicKey
	require.NoError(t, svc.refreshSigner(ctx))

	const rounds = 40
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if err := svc.refreshSigner(ctx); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			// A real signature over a real redirect-binding query string.
			if _, err := svc.signRedirectBinding("SAMLRequest=abc&SigAlg=rsa-sha256"); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
}
