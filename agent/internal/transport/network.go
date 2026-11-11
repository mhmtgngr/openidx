package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// NetworkOptions are the installer-supplied settings that decide how the agent
// reaches its server over plain HTTPS: an explicit proxy (PROXY_URL on the
// MSI, for networks with no WPAD/PAC) and an extra root to trust (SERVER_CA,
// for a server behind a private CA). Both are optional; the zero value is the
// system proxy settings and the system roots.
type NetworkOptions struct {
	ProxyURL string
	CAPEM    string
}

var (
	netMu   sync.RWMutex
	netOpts NetworkOptions
)

// SetNetworkOptions validates opts and makes them the default for every
// Client created afterwards. An invalid value is refused rather than silently
// ignored: a typo'd proxy is a device that never reaches its server.
func SetNetworkOptions(opts NetworkOptions) error {
	if _, err := opts.httpTransport(); err != nil {
		return err
	}
	netMu.Lock()
	netOpts = opts
	netMu.Unlock()
	return nil
}

func currentNetworkOptions() NetworkOptions {
	netMu.RLock()
	defer netMu.RUnlock()
	return netOpts
}

// httpTransport builds the round tripper the options describe.
func (o NetworkOptions) httpTransport() (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if p := strings.TrimSpace(o.ProxyURL); p != "" {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("proxy URL %q is not an http(s)://host[:port] URL", p)
		}
		t.Proxy = http.ProxyURL(u)
	}
	if pem := strings.TrimSpace(o.CAPEM); pem != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, fmt.Errorf("server CA holds no PEM certificate")
		}
		t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return t, nil
}

// newHTTPClient is the plain-HTTPS client every Client uses.
func newHTTPClient() *http.Client {
	c := &http.Client{Timeout: defaultTimeout}
	if t, err := currentNetworkOptions().httpTransport(); err == nil {
		c.Transport = t
	}
	return c
}
