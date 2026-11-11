package oidcrp

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// keySet is one provider's published RSA signing keys, by key id.
type keySet struct {
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	// missKid and missAt remember the last refresh forced by an unknown kid,
	// so a flood of tokens under a kid the provider does not publish costs
	// one fetch per window rather than one per token.
	missKid string
	missAt  time.Time
}

type jwksDocument struct {
	Keys []struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// signingKey returns the provider's public key with id kid from jwksURI.
//
// A fresh cached set is used as is. A set that does not know kid is
// refreshed once per key id per window: providers roll keys without notice,
// and the new key appears in the document before tokens signed by it do. A
// refresh that fails leaves a stale set in use for up to maxStale, so a
// token that still verifies keeps verifying through a provider outage.
func (d *Discoverer) signingKey(ctx context.Context, jwksURI, kid string) (*rsa.PublicKey, error) {
	d.mu.Lock()
	ks := d.keys[jwksURI]
	now := d.now()
	if ks != nil && now.Sub(ks.fetched) < d.ttl {
		if k, ok := ks.keys[kid]; ok {
			d.mu.Unlock()
			return k, nil
		}
		if ks.missKid == kid && now.Sub(ks.missAt) < keyMissRefreshWindow {
			d.mu.Unlock()
			return nil, fmt.Errorf("%w: the provider publishes no key %q", ErrSignature, kid)
		}
	}
	d.mu.Unlock()

	fresh, err := d.fetchKeys(ctx, jwksURI)

	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		if ks != nil && now.Sub(ks.fetched) < d.maxStale {
			if k, ok := ks.keys[kid]; ok {
				return k, nil
			}
		}
		return nil, err
	}
	ks = &keySet{keys: fresh, fetched: now}
	d.keys[jwksURI] = ks
	if k, ok := fresh[kid]; ok {
		return k, nil
	}
	ks.missKid, ks.missAt = kid, now
	return nil, fmt.Errorf("%w: the provider publishes no key %q", ErrSignature, kid)
}

func (d *Discoverer) fetchKeys(ctx context.Context, jwksURI string) (map[string]*rsa.PublicKey, error) {
	body, err := d.get(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeys, err)
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeys, err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pub, err := rsaKey(k.N, k.E)
		if err != nil {
			continue // one malformed key does not spoil the set
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no RSA signing keys in the document", ErrKeys)
	}
	return keys, nil
}

func rsaKey(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, err
	}
	if len(nb) == 0 || len(eb) == 0 {
		return nil, errors.New("empty modulus or exponent")
	}
	ei := new(big.Int).SetBytes(eb)
	if !ei.IsInt64() || ei.Int64() < 3 {
		return nil, errors.New("exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(ei.Int64())}, nil
}
