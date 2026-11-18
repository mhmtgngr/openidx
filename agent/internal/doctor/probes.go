package doctor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
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
	// DNSQuery sends one UDP DNS question for an A record to server (host:port)
	// and returns what, if anything, answered. A timeout is (zero, error).
	DNSQuery(ctx context.Context, server, name string) (DNSAnswer, error)
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

// DNSAnswer is the part of a DNS reply the checks look at.
type DNSAnswer struct {
	// RCode is the reply's response code (0 NOERROR, 3 NXDOMAIN, 5 REFUSED).
	RCode int
	// Answers is the number of records in the answer section.
	Answers int
}

// buildDNSQuery returns an A-record question for name, recursion desired.
func buildDNSQuery(id uint16, name string) []byte {
	pkt := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	return append(pkt, 0, 0, 1, 0, 1)
}

// parseDNSReply reads the header of a reply to the question with this id.
func parseDNSReply(id uint16, reply []byte) (DNSAnswer, error) {
	if len(reply) < 12 {
		return DNSAnswer{}, fmt.Errorf("short DNS reply")
	}
	if uint16(reply[0])<<8|uint16(reply[1]) != id || reply[2]&0x80 == 0 {
		return DNSAnswer{}, fmt.Errorf("not a reply to our question")
	}
	return DNSAnswer{RCode: int(reply[3] & 0x0f), Answers: int(reply[6])<<8 | int(reply[7])}, nil
}

func (realProbes) DNSQuery(ctx context.Context, server, name string) (DNSAnswer, error) {
	const id = 0x4f58 // "OX"
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return DNSAnswer{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(buildDNSQuery(id, name)); err != nil {
		return DNSAnswer{}, err
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return DNSAnswer{}, err
	}
	return parseDNSReply(id, buf[:n])
}
