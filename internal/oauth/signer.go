package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/signingkeys"
)

// signerSnapshot is an immutable view of the signing state: the active key
// the service signs with, every public key tokens may still carry, and the
// prebuilt JWKS document. Swapped atomically by refreshSigner.
type signerSnapshot struct {
	kid    string
	priv   *rsa.PrivateKey
	verify map[string]*rsa.PublicKey
	jwks   JWKS
}

// signingKey returns the kid and private key new tokens must be signed
// with. Falls back to the legacy single-key fields when no snapshot exists
// (unit tests construct Service directly without a database).
func (s *Service) signingKey() (string, *rsa.PrivateKey) {
	if snap := s.signer.Load(); snap != nil {
		return snap.kid, snap.priv
	}
	return signingkeys.LegacyKid, s.privateKey
}

// verificationKeyfunc is the jwt.Keyfunc for tokens this service issued. It
// resolves the token's kid against the current verification set; an unknown
// kid triggers one snapshot refresh (another replica may have rotated) before
// failing. Tokens without a kid header verify against the active key, which
// keeps pre-upgrade tokens and legacy test tokens working.
func (s *Service) verificationKeyfunc(token *jwt.Token) (interface{}, error) {
	snap := s.signer.Load()
	if snap == nil {
		return s.publicKey, nil
	}
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return &snap.priv.PublicKey, nil
	}
	if pub, ok := snap.verify[kid]; ok {
		return pub, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.refreshSigner(ctx); err == nil {
		if snap = s.signer.Load(); snap != nil {
			if pub, ok := snap.verify[kid]; ok {
				return pub, nil
			}
		}
	}
	return nil, fmt.Errorf("unknown signing key id %q", kid)
}

// refreshSigner rebuilds the snapshot from oauth_signing_keys.
func (s *Service) refreshSigner(ctx context.Context) error {
	keys, err := s.keyStore.VerificationKeys(ctx)
	if err != nil {
		return fmt.Errorf("load verification keys: %w", err)
	}
	if len(keys) == 0 || keys[0].Status != "active" {
		return fmt.Errorf("no active signing key")
	}
	snap := &signerSnapshot{
		kid:    keys[0].Kid,
		priv:   keys[0].Private,
		verify: make(map[string]*rsa.PublicKey, len(keys)),
	}
	for _, k := range keys {
		pub := &k.Private.PublicKey
		snap.verify[k.Kid] = pub
		snap.jwks.Keys = append(snap.jwks.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Kid: k.Kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString([]byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)}),
		})
	}
	s.signer.Store(snap)
	// Keep the legacy fields tracking the active key for any direct readers.
	s.privateKey = snap.priv
	s.publicKey = &snap.priv.PublicKey
	return nil
}

// signerRefreshLoop re-reads the key set periodically so a rotation
// performed by the admin service is picked up without a restart (new tokens
// switch to the new key within one interval; the retired key stays valid for
// verification throughout its grace). Also prunes retired keys whose grace
// has expired.
func (s *Service) signerRefreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := s.refreshSigner(refreshCtx); err != nil {
				s.logger.Warn("signing key refresh failed; continuing with current key set", zap.Error(err))
			}
			if n, err := s.keyStore.PruneExpired(refreshCtx); err == nil && n > 0 {
				s.logger.Info("pruned expired retired signing keys", zap.Int64("count", n))
			}
			cancel()
		}
	}
}
