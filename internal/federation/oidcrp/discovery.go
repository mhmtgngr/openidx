// Package oidcrp is OpenIDX acting as an OpenID Connect relying party to an
// upstream identity provider: Microsoft Entra ID, ADFS, Keycloak, a partner
// organization's own issuer.
//
// Everything the relying party trusts about a provider comes from two
// documents the provider publishes, its discovery document and its key set,
// and from checks the OpenID Connect Core specification requires of every ID
// token: issuer, audience, signature, lifetime and nonce. Before this package
// the sign-in path built Keycloak's endpoint paths by hand, verified only the
// signature, and fetched the upstream key set through the verifier that
// caches OpenIDX's OWN signing keys, so one upstream fetch replaced the
// install's key cache. Each Discoverer keeps its own caches, one per
// discovery URL and one per JWKS URI, and never touches the install's.
package oidcrp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Metadata is the part of an OpenID provider's discovery document the relying
// party uses.
type Metadata struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint               string   `json:"end_session_endpoint,omitempty"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

// SupportsPKCE reports whether the provider advertises the S256 code
// challenge method. A provider that advertises nothing may still accept it;
// callers decide whether to send PKCE regardless.
func (m *Metadata) SupportsPKCE() bool {
	for _, c := range m.CodeChallengeMethodsSupported {
		if c == "S256" {
			return true
		}
	}
	return false
}

// Refusals a caller can tell apart.
var (
	ErrIssuerMismatch = errors.New("the discovery document names a different issuer")
	ErrInsecureIssuer = errors.New("an issuer must use https")
	ErrDiscovery      = errors.New("the provider's discovery document could not be read")
	ErrKeys           = errors.New("the provider's keys could not be read")
)

// WellKnownPath is where OpenID Connect Discovery 1.0 puts the document.
const WellKnownPath = "/.well-known/openid-configuration"

const (
	defaultMetadataTTL   = time.Hour
	defaultMaxStale      = 24 * time.Hour
	defaultHTTPTimeout   = 10 * time.Second
	maxDocumentBytes     = 1 << 20
	keyMissRefreshWindow = 30 * time.Second
)

// Discoverer reads and caches provider metadata and keys. The zero value is
// not usable; use NewDiscoverer. One Discoverer serves any number of
// providers; a process normally holds one.
type Discoverer struct {
	client   *http.Client
	ttl      time.Duration
	maxStale time.Duration
	now      func() time.Time

	mu       sync.Mutex
	metadata map[string]*cachedMetadata // by discovery URL
	keys     map[string]*keySet         // by JWKS URI
}

type cachedMetadata struct {
	md      *Metadata
	fetched time.Time
}

// NewDiscoverer returns a Discoverer using client, or GuardedClient when nil:
// an issuer is a URL an administrator types in, so by default it may not name
// an internal address.
func NewDiscoverer(client *http.Client) *Discoverer {
	if client == nil {
		client, _ = GuardedClient()
	}
	return &Discoverer{
		client:   client,
		ttl:      defaultMetadataTTL,
		maxStale: defaultMaxStale,
		now:      time.Now,
		metadata: map[string]*cachedMetadata{},
		keys:     map[string]*keySet{},
	}
}

// Discover returns the provider metadata for issuer. discoveryURL names the
// document when the provider does not publish it at
// <issuer>/.well-known/openid-configuration (ADFS puts it under /adfs/);
// empty means the standard location. The document's issuer must be the one
// asked for: a document that names another issuer is somebody else's
// provider, however it was reached.
//
// Metadata is cached for an hour and served from cache for up to a day when
// the provider is unreachable, so a provider outage does not take sign-in
// down with it for tokens that still verify.
func (d *Discoverer) Discover(ctx context.Context, issuer, discoveryURL string) (*Metadata, error) {
	issuer = strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	if err := checkIssuerURL(issuer); err != nil {
		return nil, err
	}
	if discoveryURL == "" {
		discoveryURL = issuer + WellKnownPath
	} else if err := checkIssuerURL(discoveryURL); err != nil {
		return nil, fmt.Errorf("discovery url: %w", err)
	}

	d.mu.Lock()
	c := d.metadata[discoveryURL]
	if c != nil && d.now().Sub(c.fetched) < d.ttl {
		d.mu.Unlock()
		return c.md, nil
	}
	d.mu.Unlock()

	md, err := d.fetchMetadata(ctx, discoveryURL)
	if err != nil {
		if c != nil && d.now().Sub(c.fetched) < d.maxStale {
			return c.md, nil
		}
		return nil, err
	}
	if !sameIssuer(md.Issuer, issuer) {
		return nil, fmt.Errorf("%w: document says %q, configured %q", ErrIssuerMismatch, md.Issuer, issuer)
	}
	if md.AuthorizationEndpoint == "" || md.JWKSURI == "" {
		return nil, fmt.Errorf("%w: no authorization_endpoint or jwks_uri", ErrDiscovery)
	}
	for _, u := range []string{md.AuthorizationEndpoint, md.TokenEndpoint, md.JWKSURI} {
		if u == "" {
			continue
		}
		if err := checkIssuerURL(u); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
		}
	}

	d.mu.Lock()
	d.metadata[discoveryURL] = &cachedMetadata{md: md, fetched: d.now()}
	d.mu.Unlock()
	return md, nil
}

func (d *Discoverer) fetchMetadata(ctx context.Context, discoveryURL string) (*Metadata, error) {
	body, err := d.get(ctx, discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	var md Metadata
	if err := json.Unmarshal(body, &md); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	return &md, nil
}

// get reads at most maxDocumentBytes from url with a 200 response.
func (d *Discoverer) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDocumentBytes {
		return nil, errors.New("document larger than 1 MiB")
	}
	return body, nil
}

// checkIssuerURL requires an absolute https URL without query or fragment.
// Plain http is allowed only on loopback, for tests and local development.
func checkIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: %q is not an absolute URL", ErrInsecureIssuer, raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: %q carries a query or fragment", ErrInsecureIssuer, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if loopbackAllowed() && (host == "localhost" || net.ParseIP(host).IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrInsecureIssuer, raw)
}

// sameIssuer compares two issuer identifiers, allowing only a trailing slash
// to differ. The OpenID Connect discovery specification wants the values
// character for character; the slash is the one difference operators type
// by accident and providers disagree on.
func sameIssuer(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}
