package oauth

// Signing keys for the Entra external authentication method (eam.go).
//
// Entra fetches <issuer>/eam/jwks, wants an x5c certificate on every key, and
// caches what it fetched. A key therefore has two moments: when it is
// PUBLISHED (the row exists and /eam/jwks lists it) and when it starts to
// SIGN (not_before). The first key an install ever makes signs at once, since
// nothing has cached anything yet. A rotation publishes the next key and lets
// it sign only eamKeyPublishLead later, so every Entra cache has seen it by
// the time an id_token names it. The previous key stays published until its
// certificate expires.
//
// These keys are not the platform's token signing keys: they sign only the
// id_token handed back to one Entra application, and rotate on Entra's
// schedule. The private key is stored as PEM sealed with the install's secret
// cipher (the one identity provider secrets use).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
	"github.com/openidx/openidx/internal/common/secretcrypt"
)

const (
	// eamKeyPublishLead is how long a rotated key is published before it
	// signs. Entra documents caching the provider's keys; two days is the
	// margin the runbook gives it.
	eamKeyPublishLead = 48 * time.Hour
	// eamKeyLifetime is the certificate's validity, and how long the key
	// stays in the published set.
	eamKeyLifetime = 2 * 365 * 24 * time.Hour
)

var errNoEAMKey = errors.New("eam: no signing key")

// eamKey is one row of eam_signing_keys, decrypted.
type eamKey struct {
	ID        string
	KID       string
	Private   *rsa.PrivateKey
	CertDER   []byte
	NotBefore time.Time // when it starts to sign
	NotAfter  time.Time // when the certificate expires and it leaves the set
	Active    bool
	CreatedAt time.Time
}

func (s *Service) eamCipher() *secretcrypt.Cipher {
	if s.idpCipher != nil {
		return s.idpCipher
	}
	return secretcrypt.NewNoop()
}

// newEAMKey generates an RSA-2048 key and a self-signed certificate for it.
// signsFrom is the not_before the row records.
func newEAMKey(issuer string, now, signsFrom time.Time) (*eamKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(eamKeyLifetime)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "OpenIDX EAM " + issuer},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &eamKey{
		KID:       "eam-" + hex.EncodeToString(sum[:8]),
		Private:   priv,
		CertDER:   der,
		NotBefore: signsFrom,
		NotAfter:  notAfter,
	}, nil
}

func (s *Service) insertEAMKey(ctx context.Context, k *eamKey, active bool) error {
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k.Private)})
	sealed, err := s.eamCipher().Encrypt(string(keyPEM))
	if err != nil {
		return fmt.Errorf("eam: seal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.CertDER})
	return s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
		`INSERT INTO eam_signing_keys (kid, private_key_enc, cert_pem, not_before, not_after, active)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text, created_at`,
		k.KID, sealed, string(certPEM), k.NotBefore, k.NotAfter, active).Scan(&k.ID, &k.CreatedAt)
}

// loadEAMKeys returns every published key (certificate not yet expired),
// newest first.
func (s *Service) loadEAMKeys(ctx context.Context, now time.Time) ([]*eamKey, error) {
	rows, err := s.db.Pool.Query(orgctx.WithBypassRLS(ctx),
		`SELECT id::text, kid, private_key_enc, cert_pem, not_before, not_after, active, created_at
		   FROM eam_signing_keys WHERE not_after > $1 ORDER BY not_before DESC, created_at DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*eamKey
	for rows.Next() {
		var k eamKey
		var sealed, certPEM string
		if err := rows.Scan(&k.ID, &k.KID, &sealed, &certPEM, &k.NotBefore, &k.NotAfter, &k.Active, &k.CreatedAt); err != nil {
			return nil, err
		}
		plain, err := s.eamCipher().Decrypt(sealed)
		if err != nil {
			return nil, fmt.Errorf("eam: open key %s: %w", k.KID, err)
		}
		kb, _ := pem.Decode([]byte(plain))
		if kb == nil {
			return nil, fmt.Errorf("eam: key %s is not PEM", k.KID)
		}
		if k.Private, err = x509.ParsePKCS1PrivateKey(kb.Bytes); err != nil {
			return nil, fmt.Errorf("eam: key %s: %w", k.KID, err)
		}
		cb, _ := pem.Decode([]byte(certPEM))
		if cb == nil {
			return nil, fmt.Errorf("eam: certificate of %s is not PEM", k.KID)
		}
		k.CertDER = cb.Bytes
		out = append(out, &k)
	}
	return out, rows.Err()
}

// ensureEAMKeys returns the published keys, creating the first one (signing
// at once) when there are none.
func (s *Service) ensureEAMKeys(ctx context.Context, now time.Time) ([]*eamKey, error) {
	keys, err := s.loadEAMKeys(ctx, now)
	if err != nil || len(keys) > 0 {
		return keys, err
	}
	k, err := newEAMKey(s.eamIssuer(), now, now)
	if err != nil {
		return nil, err
	}
	if err := s.insertEAMKey(ctx, k, true); err != nil {
		// A concurrent first request may have won; read what it wrote.
		if keys, lerr := s.loadEAMKeys(ctx, now); lerr == nil && len(keys) > 0 {
			return keys, nil
		}
		return nil, err
	}
	k.Active = true
	return []*eamKey{k}, nil
}

// eamSigningKey picks the key that signs now: the newest published key whose
// not_before has passed. It records the choice in the active column, so the
// console reads which key signs without repeating the rule.
func (s *Service) eamSigningKey(ctx context.Context, now time.Time) (*eamKey, error) {
	keys, err := s.ensureEAMKeys(ctx, now)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if !k.NotBefore.After(now) {
			if !k.Active {
				if _, err := s.db.Pool.Exec(orgctx.WithBypassRLS(ctx),
					`UPDATE eam_signing_keys SET active = (id = $1::uuid)`, k.ID); err != nil {
					s.logger.Warn("eam: could not record the signing key", zap.Error(err))
				}
				k.Active = true
			}
			return k, nil
		}
	}
	return nil, errNoEAMKey
}

// rotateEAMKey publishes a new key that signs eamKeyPublishLead from now.
func (s *Service) rotateEAMKey(ctx context.Context, now time.Time) (*eamKey, error) {
	if _, err := s.ensureEAMKeys(ctx, now); err != nil {
		return nil, err
	}
	k, err := newEAMKey(s.eamIssuer(), now, now.Add(eamKeyPublishLead))
	if err != nil {
		return nil, err
	}
	if err := s.insertEAMKey(ctx, k, false); err != nil {
		return nil, err
	}
	return k, nil
}

// eamJWK is one key of /eam/jwks, with its certificate chain (x5c) and
// thumbprint (x5t), which Entra reads.
type eamJWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	Kid string   `json:"kid"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
}

func (k *eamKey) jwk() eamJWK {
	pub := k.Private.PublicKey
	thumb := sha1Thumbprint(k.CertDER)
	return eamJWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: k.KID,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		X5c: []string{base64.StdEncoding.EncodeToString(k.CertDER)},
		X5t: thumb,
	}
}

// eamKeyView is what the key management API reports about a key.
type eamKeyView struct {
	KID       string    `json:"kid"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

func (k *eamKey) view() eamKeyView {
	return eamKeyView{KID: k.KID, NotBefore: k.NotBefore, NotAfter: k.NotAfter, Active: k.Active, CreatedAt: k.CreatedAt}
}

// handleListEAMKeys: GET /api/v1/oauth/eam/keys (platform administrators).
func (s *Service) handleListEAMKeys(c *gin.Context) {
	keys, err := s.loadEAMKeys(c.Request.Context(), time.Now())
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.logger.Error("eam: list keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	out := make([]eamKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.view())
	}
	c.JSON(http.StatusOK, gin.H{"keys": out})
}

// handleRotateEAMKey: POST /api/v1/oauth/eam/keys/rotate (platform
// administrators). The new key is published now and signs two days later.
func (s *Service) handleRotateEAMKey(c *gin.Context) {
	k, err := s.rotateEAMKey(c.Request.Context(), time.Now())
	if err != nil {
		s.logger.Error("eam: rotate key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	s.logAuditEvent(c.Request.Context(), "configuration", "security", "eam.key_rotated", "success",
		c.GetString("user_id"), c.ClientIP(), k.KID, "eam_signing_key",
		map[string]interface{}{"kid": k.KID, "signs_from": k.NotBefore})
	c.JSON(http.StatusCreated, k.view())
}

// eamStatus is the console's view of the Entra external method: what to
// register in Entra, the keys, the tenants and recent use.
type eamStatus struct {
	Enabled                bool         `json:"enabled"`
	Issuer                 string       `json:"issuer"`
	DiscoveryURL           string       `json:"discovery_url"`
	JWKSURL                string       `json:"jwks_url"`
	AuthorizeURL           string       `json:"authorize_url"`
	ClientID               string       `json:"client_id"`
	TenantIDs              []string     `json:"tenant_ids"`
	RequireStrongFactors   bool         `json:"require_strong_factors"`
	Keys                   []eamKeyView `json:"keys"`
	Verifications24h       int64        `json:"verifications_24h"`
	VerificationsFailed24h int64        `json:"verifications_failed_24h"`
}

func (s *Service) eamStatusView() eamStatus {
	iss := s.eamIssuer()
	st := eamStatus{
		Enabled:      s.eamEnabled(),
		Issuer:       iss,
		DiscoveryURL: iss + "/.well-known/openid-configuration",
		JWKSURL:      iss + "/jwks",
		AuthorizeURL: iss + "/authorize",
		ClientID:     s.eamClientID(),
		TenantIDs:    []string{},
		Keys:         []eamKeyView{},
	}
	if s.config != nil {
		st.RequireStrongFactors = s.config.EAMRequireStrongFactors
		for _, t := range strings.Split(s.config.EAMTenantIDs, ",") {
			if t = strings.TrimSpace(t); t != "" {
				st.TenantIDs = append(st.TenantIDs, t)
			}
		}
	}
	return st
}

// handleEAMStatus: GET /api/v1/oauth/eam/status (platform administrators).
// Keys are listed without being created: looking does not mint a key.
func (s *Service) handleEAMStatus(c *gin.Context) {
	st := s.eamStatusView()
	if s.db != nil && s.db.Pool != nil {
		ctx := c.Request.Context()
		keys, err := s.loadEAMKeys(ctx, time.Now())
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Error("eam: status keys", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		for _, k := range keys {
			st.Keys = append(st.Keys, k.view())
		}
		if err := s.db.Pool.QueryRow(orgctx.WithBypassRLS(ctx),
			//orgscope:ignore EAM status is install-wide: one Entra app counts verifications across every organization
			`SELECT COUNT(*) FILTER (WHERE action = 'eam.mfa_satisfied'),
			        COUNT(*) FILTER (WHERE action IN ('eam.mfa_refused', 'eam.mfa_failed'))
			   FROM audit_events
			  WHERE action IN ('eam.mfa_satisfied', 'eam.mfa_refused', 'eam.mfa_failed')
			    AND timestamp > NOW() - INTERVAL '24 hours'`,
		).Scan(&st.Verifications24h, &st.VerificationsFailed24h); err != nil {
			s.logger.Warn("eam: status count", zap.Error(err))
		}
	}
	c.JSON(http.StatusOK, st)
}
