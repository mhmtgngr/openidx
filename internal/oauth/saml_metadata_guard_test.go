package oauth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/netutil"
)

// A SAML SERVICE PROVIDER'S METADATA URL IS AN ORGANIZATION ADMINISTRATOR'S,
// and what the fetch returns is parsed into the registration they read back.
// The fetch goes through the outbound guard: a URL on the platform's own
// network is refused before anything is requested, a redirect into it is
// refused at the connection, and a public metadata host still answers.
func TestSAMLMetadataIsFetchedFromPublicHostsOnly(t *testing.T) {
	var internalHits atomic.Int64
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		_, _ = w.Write([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="internal-secret"/>`))
	}))
	defer internal.Close()
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.test/saml"/>`))
	}))
	defer metadata.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/metadata", http.StatusFound)
	}))
	defer redirector.Close()

	var d net.Dialer
	guard := netutil.NewOutboundGuard(netutil.Allowlist{}).WithProxy(nil).
		WithResolver(netutil.ResolverFunc(func(_ context.Context, _, host string) ([]netip.Addr, error) {
			switch host {
			case "sp.example.test":
				return []netip.Addr{netip.MustParseAddr("203.0.113.60")}, nil
			case "redirect.example.test":
				return []netip.Addr{netip.MustParseAddr("203.0.113.61")}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		})).
		WithDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
			switch address {
			case "203.0.113.60:80":
				address = metadata.Listener.Addr().String()
			case "203.0.113.61:80":
				address = redirector.Listener.Addr().String()
			}
			return d.DialContext(ctx, network, address)
		})
	prev := orgOutboundGuard
	orgOutboundGuard = func() *netutil.OutboundGuard { return guard }
	t.Cleanup(func() { orgOutboundGuard = prev })

	s := &Service{logger: zap.NewNop()}
	ctx := context.Background()

	if _, err := s.FetchSAMLMetadata(ctx, internal.URL+"/metadata"); err == nil ||
		!strings.Contains(err.Error(), "metadata URL is not allowed") || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("fetching metadata from loopback = %v, want a refusal naming loopback", err)
	}
	if _, err := s.FetchSAMLMetadata(ctx, "http://redirect.example.test/metadata"); err == nil ||
		!strings.Contains(err.Error(), "loopback") {
		t.Errorf("fetching metadata through a redirect to loopback = %v, want it refused at the connection", err)
	}
	if n := internalHits.Load(); n != 0 {
		t.Errorf("the internal server was reached %d times", n)
	}

	md, err := s.FetchSAMLMetadata(ctx, "http://sp.example.test/metadata")
	if err != nil || md.EntityID != "https://sp.example.test/saml" {
		t.Fatalf("fetching public metadata = %+v, %v", md, err)
	}
}
