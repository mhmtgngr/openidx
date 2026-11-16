package doctor

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/openidx/openidx/agent/internal/transport"
)

// probeTimeout bounds every single probe; a variable so tests can shorten it.
var probeTimeout = 5 * time.Second

// MaxClockSkew is how far the device clock may differ from the server's.
const MaxClockSkew = 5 * time.Minute

// HTTPResult is what an unauthenticated request to the server showed.
type HTTPResult struct {
	Status int
	Date   time.Time
}

// Probes is everything the checks ask of the outside world.
type Probes interface {
	Resolve(ctx context.Context, host string) ([]string, error)
	DialTCP(ctx context.Context, hostport string) error
	TLSHandshake(ctx context.Context, hostport, serverName string) error
	HTTPGet(ctx context.Context, url string) (HTTPResult, error)
	// Proxy is the proxy a request to rawURL would use, or nil.
	Proxy(rawURL string) *url.URL
	Now() time.Time
}

type realProbes struct{}

// NewProbes returns probes over the real network, using the agent's shared
// transport so the configured proxy and server CA apply.
func NewProbes() Probes { return realProbes{} }

func (realProbes) Resolve(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (realProbes) DialTCP(ctx context.Context, hostport string) error {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return err
	}
	return c.Close()
}

func (realProbes) TLSHandshake(ctx context.Context, hostport, serverName string) error {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if base := transport.SharedTransport().TLSClientConfig; base != nil {
		cfg = base.Clone()
	}
	cfg.ServerName = serverName
	d := tls.Dialer{Config: cfg}
	c, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return err
	}
	return c.Close()
}

func (realProbes) HTTPGet(ctx context.Context, rawURL string) (HTTPResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return HTTPResult{}, err
	}
	client := &http.Client{
		Transport: transport.SharedTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return HTTPResult{}, err
	}
	defer resp.Body.Close()
	res := HTTPResult{Status: resp.StatusCode}
	if d, perr := http.ParseTime(resp.Header.Get("Date")); perr == nil {
		res.Date = d
	}
	return res, nil
}

func (realProbes) Proxy(rawURL string) *url.URL {
	proxy := transport.SharedTransport().Proxy
	if proxy == nil {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	u, err := proxy(req)
	if err != nil {
		return nil
	}
	return u
}

func (realProbes) Now() time.Time { return time.Now() }
