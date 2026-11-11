package oidcrp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Refusals of an ID token, each one check of OpenID Connect Core §3.1.3.7.
var (
	ErrMalformed   = errors.New("the ID token is not a JWT")
	ErrAlgorithm   = errors.New("the ID token is not signed with an accepted algorithm")
	ErrSignature   = errors.New("the ID token's signature does not verify against the provider's keys")
	ErrIssuer      = errors.New("the ID token was issued by somebody else")
	ErrAudience    = errors.New("the ID token was not issued to this client")
	ErrNonce       = errors.New("the ID token does not answer this sign-in")
	ErrExpired     = errors.New("the ID token has expired")
	ErrNotYetValid = errors.New("the ID token is not valid yet")
)

// acceptedAlgs are the signing algorithms an upstream ID token may carry.
// Every provider this package exists for signs RS256; the other two cost
// nothing to accept. HMAC is refused: a provider sharing its HMAC key with a
// relying party could not then prove the token came from the provider.
var acceptedAlgs = map[string]bool{"RS256": true, "RS384": true, "RS512": true}

// VerifyOptions is what the relying party knows about the sign-in it is
// completing.
type VerifyOptions struct {
	// ClientID is this relying party's client id at the provider; the token's
	// audience must name it.
	ClientID string
	// Nonce is the value sent in the authorization request; the token must
	// carry it back. Empty means none was sent, and a nonce in the token is
	// then not checked.
	Nonce string
	// AllowExpired accepts a token past its exp. Entra's id_token_hint for an
	// external MFA method is issued already expired, by design; nothing else
	// should set this.
	AllowExpired bool
	// Skew tolerates clock drift between the provider and this host; two
	// minutes when zero.
	Skew time.Duration
	// Now overrides the clock; the Discoverer's when zero.
	Now time.Time
}

// Claims is a verified ID token's content. The standard and Microsoft
// claims the sign-in path reads are typed; Raw keeps everything for the
// operator's claims mapping.
type Claims struct {
	Sub               string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	UPN               string
	OID               string // Microsoft: the user's object id, stable across applications
	TID               string // Microsoft: the tenant id
	Name              string
	GivenName         string
	FamilyName        string
	Groups            []string
	Roles             []string
	AMR               []string
	ACR               string
	AuthTime          time.Time
	Raw               map[string]any
}

// VerifyIDToken checks raw against md and opts and returns its claims. The
// checks, in order: well-formed JWT, accepted algorithm, signature by a key
// the provider publishes, issuer, audience (and azp when there are several),
// lifetime, nonce.
func (d *Discoverer) VerifyIDToken(ctx context.Context, md *Metadata, raw string, opts VerifyOptions) (*Claims, error) {
	alg, kid, err := header(raw)
	if err != nil {
		return nil, err
	}
	if !acceptedAlgs[alg] {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, alg)
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{alg}), jwt.WithoutClaimsValidation())
	var claims jwt.MapClaims
	tok, err := parser.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		return d.signingKey(ctx, md.JWKSURI, kid)
	})
	if err != nil {
		if errors.Is(err, ErrSignature) || errors.Is(err, ErrKeys) {
			return nil, err
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if !tok.Valid {
		return nil, ErrSignature
	}

	iss, _ := claims["iss"].(string)
	if !sameIssuer(iss, md.Issuer) {
		return nil, fmt.Errorf("%w: %q", ErrIssuer, iss)
	}

	aud := stringList(claims["aud"])
	if !contains(aud, opts.ClientID) {
		return nil, fmt.Errorf("%w: aud %v", ErrAudience, aud)
	}
	if len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != "" && azp != opts.ClientID {
			return nil, fmt.Errorf("%w: azp %q", ErrAudience, azp)
		}
	}

	now := opts.Now
	if now.IsZero() {
		now = d.now()
	}
	skew := opts.Skew
	if skew == 0 {
		skew = 2 * time.Minute
	}
	exp, hasExp := numericDate(claims["exp"])
	if !hasExp && !opts.AllowExpired {
		return nil, fmt.Errorf("%w: no exp", ErrExpired)
	}
	if hasExp && !opts.AllowExpired && now.After(exp.Add(skew)) {
		return nil, ErrExpired
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && nbf.After(now.Add(skew)) {
		return nil, ErrNotYetValid
	}
	if iat, ok := numericDate(claims["iat"]); ok && iat.After(now.Add(skew)) {
		return nil, fmt.Errorf("%w: issued in the future", ErrNotYetValid)
	}

	if opts.Nonce != "" {
		if n, _ := claims["nonce"].(string); n != opts.Nonce {
			return nil, ErrNonce
		}
	}

	c := &Claims{
		Sub:               str(claims, "sub"),
		Email:             str(claims, "email"),
		EmailVerified:     boolean(claims["email_verified"]),
		PreferredUsername: str(claims, "preferred_username"),
		UPN:               str(claims, "upn"),
		OID:               str(claims, "oid"),
		TID:               str(claims, "tid"),
		Name:              str(claims, "name"),
		GivenName:         str(claims, "given_name"),
		FamilyName:        str(claims, "family_name"),
		Groups:            stringList(claims["groups"]),
		Roles:             stringList(claims["roles"]),
		AMR:               stringList(claims["amr"]),
		ACR:               str(claims, "acr"),
		Raw:               map[string]any(claims),
	}
	if at, ok := numericDate(claims["auth_time"]); ok {
		c.AuthTime = at
	}
	if c.Sub == "" {
		return nil, fmt.Errorf("%w: no sub", ErrMalformed)
	}
	return c, nil
}

// header decodes the JOSE header without verifying anything.
func header(raw string) (alg, kid string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("%w: %d segments", ErrMalformed, len(parts))
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return "", "", fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	return h.Alg, h.Kid, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func boolean(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return time.Unix(i, 0), true
		}
	case int64:
		return time.Unix(n, 0), true
	}
	return time.Time{}, false
}

// stringList reads a claim that may be one string, a list of strings, or a
// space-separated string (how some providers send scopes and groups).
func stringList(v any) []string {
	switch l := v.(type) {
	case nil:
		return nil
	case string:
		if l == "" {
			return nil
		}
		return strings.Fields(l)
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}
