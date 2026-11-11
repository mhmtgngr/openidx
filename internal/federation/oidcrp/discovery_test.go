package oidcrp

import (
	"context"
	"errors"
	"testing"
)

func TestDiscoverReadsTheProviderMetadata(t *testing.T) {
	p := newFakeProvider(t)
	d := NewDiscoverer(nil)

	md, err := d.Discover(context.Background(), p.srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if md.Issuer != p.srv.URL || md.AuthorizationEndpoint != p.srv.URL+"/authorize" ||
		md.TokenEndpoint != p.srv.URL+"/token" || md.JWKSURI != p.srv.URL+"/keys" {
		t.Errorf("metadata = %+v", md)
	}
	if !md.SupportsPKCE() {
		t.Error("S256 advertised but SupportsPKCE false")
	}
}

func TestDiscoverRefusesAnIssuerThatDoesNotMatch(t *testing.T) {
	p := newFakeProvider(t)
	p.issuer = "https://somebody-else.example"
	d := NewDiscoverer(nil)

	_, err := d.Discover(context.Background(), p.srv.URL, "")
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("err = %v, want ErrIssuerMismatch", err)
	}
}

func TestDiscoverIsCachedPerIssuer(t *testing.T) {
	p := newFakeProvider(t)
	d := NewDiscoverer(nil)
	for i := 0; i < 3; i++ {
		if _, err := d.Discover(context.Background(), p.srv.URL, ""); err != nil {
			t.Fatal(err)
		}
	}
	if n := p.discovery.Load(); n != 1 {
		t.Errorf("discovery fetched %d times, want 1", n)
	}
}

func TestDiscoverHonoursAnExplicitDiscoveryURL(t *testing.T) {
	// ADFS publishes its document under /adfs/.well-known/..., and an
	// operator may name it; the issuer check still applies.
	p := newFakeProvider(t)
	d := NewDiscoverer(nil)
	md, err := d.Discover(context.Background(), p.srv.URL, p.srv.URL+"/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	if md.Issuer != p.srv.URL {
		t.Errorf("issuer = %q", md.Issuer)
	}
}

func TestDiscoverRequiresHTTPS(t *testing.T) {
	// The fake provider is plain http; the loopback exception is what lets
	// the other tests run at all. A real issuer on http is refused.
	d := NewDiscoverer(nil)
	_, err := d.Discover(context.Background(), "http://idp.example.org", "")
	if !errors.Is(err, ErrInsecureIssuer) {
		t.Fatalf("err = %v, want ErrInsecureIssuer", err)
	}
}
