package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NetworkOptions are the installer-supplied settings that decide how the agent
// reaches its server over plain HTTPS: an explicit proxy (PROXY_URL on the
// MSI, for networks with no WPAD/PAC) and an extra root to trust (SERVER_CA,
// for a server behind a private CA). Both are optional; the zero value is the
// system proxy settings and the system roots.
//
// Proxy resolution order: ProxyURL, then the HTTPS_PROXY/HTTP_PROXY/NO_PROXY
// environment, then (Windows only) the machine WinHTTP proxy
// (`netsh winhttp set proxy`, the WinHttpSettings registry value). PAC/WPAD
// is NOT evaluated; a PAC-only network needs PROXY_URL.
type NetworkOptions struct {
	ProxyURL string
	CAPEM    string
}

var (
	netMu     sync.RWMutex
	netOpts   NetworkOptions
	sharedRT  *http.Transport
	sharedErr error
)

// SetNetworkOptions validates opts and makes them the default for every
// client created afterwards, and rebuilds the single shared transport. An
// invalid value is refused rather than silently ignored: a typo'd proxy is a
// device that never reaches its server.
func SetNetworkOptions(opts NetworkOptions) error {
	t, err := opts.httpTransport()
	if err != nil {
		return err
	}
	netMu.Lock()
	old := sharedRT
	netOpts = opts
	sharedRT, sharedErr = t, nil
	netMu.Unlock()
	if old != nil {
		old.CloseIdleConnections()
	}
	return nil
}

func currentNetworkOptions() NetworkOptions {
	netMu.RLock()
	defer netMu.RUnlock()
	return netOpts
}

// SharedTransport is the one http.Transport the agent uses for every
// plain-HTTPS call: the control-plane client, the updater and SSO. Sharing it
// means one connection pool and one place where proxy and trust are decided.
func SharedTransport() *http.Transport {
	netMu.RLock()
	t := sharedRT
	netMu.RUnlock()
	if t != nil {
		return t
	}
	netMu.Lock()
	defer netMu.Unlock()
	if sharedRT == nil {
		sharedRT, sharedErr = netOpts.httpTransport()
		if sharedErr != nil {
			sharedRT, _ = NetworkOptions{}.httpTransport()
		}
	}
	return sharedRT
}

// HTTPClient returns a client over SharedTransport with the given timeout
// (zero means no timeout, for large downloads bounded by their context).
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: SharedTransport(), Timeout: timeout}
}

// httpTransport builds the round tripper the options describe.
func (o NetworkOptions) httpTransport() (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = systemProxy()
	if p := strings.TrimSpace(o.ProxyURL); p != "" {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("proxy URL %q is not an http(s)://host[:port] URL", p)
		}
		t.Proxy = http.ProxyURL(u)
	}
	if pem := strings.TrimSpace(o.CAPEM); pem != "" {
		pool, err := rootPoolWith(pem)
		if err != nil {
			return nil, err
		}
		t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return t, nil
}

// rootPoolWith returns the system roots plus the certificates in pem. The
// server CA is appended, never a replacement: a private CA must not make the
// agent distrust every public endpoint (updates, OAuth providers).
func rootPoolWith(pem string) (*x509.CertPool, error) {
	pool, err := systemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		return nil, fmt.Errorf("server CA holds no PEM certificate")
	}
	return pool, nil
}

var systemCertPool = x509.SystemCertPool

// systemProxy is the environment proxy, falling back to the OS machine proxy
// (WinHTTP on Windows; nothing elsewhere).
func systemProxy() func(*http.Request) (*url.URL, error) {
	machine := machineProxy()
	return func(r *http.Request) (*url.URL, error) {
		if u, err := http.ProxyFromEnvironment(r); u != nil || err != nil || envProxySet() {
			return u, err
		}
		if machine != nil {
			return machine.proxyFor(r.URL), nil
		}
		return nil, nil
	}
}

func envProxySet() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if strings.TrimSpace(getenv(k)) != "" {
			return true
		}
	}
	return false
}

// newHTTPClient is the plain-HTTPS client every Client uses.
func newHTTPClient() *http.Client {
	return HTTPClient(defaultTimeout)
}
