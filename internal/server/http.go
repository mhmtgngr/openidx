package server

import (
	"net/http"
	"time"
)

// Hardened defaults every OpenIDX listener gets (global-scale plan task 0.3).
//
// The slow-request family of attacks (slowloris, slow headers, slow body,
// HTTP/2 stream floods) does not need bandwidth: it needs the server to keep a
// connection's state alive while the client trickles bytes. Go's http.Server
// keeps such a connection forever unless told otherwise. Each service used to
// build its own http.Server literal with Read/Write/Idle timeouts and nothing
// else — seven mains, seven chances to forget the header timeout, and all
// seven forgot it. This constructor is the one place the floor is set.
const (
	// DefaultReadHeaderTimeout bounds the time from the first byte of a request
	// to the end of its headers. Legitimate clients send headers in one packet;
	// five seconds is generous over any real network and still starves a
	// slowloris that sends one header line a minute.
	DefaultReadHeaderTimeout = 5 * time.Second
	// DefaultMaxHeaderBytes caps the request line plus headers. 16 KiB fits
	// every cookie jar and bearer token this product issues several times
	// over; Go's own default is 1 MiB, which is a per-connection allocation an
	// attacker chooses the size of.
	DefaultMaxHeaderBytes = 16 << 10
	// DefaultMaxConcurrentStreams caps HTTP/2 streams per connection. 100 is
	// the RFC's suggested minimum and what browsers use; a client opening
	// thousands of streams per connection is a rapid-reset flood, not a user.
	DefaultMaxConcurrentStreams = 100

	DefaultReadTimeout  = 15 * time.Second
	DefaultWriteTimeout = 15 * time.Second
	DefaultIdleTimeout  = 60 * time.Second
)

// HTTPOptions are the per-service knobs. Zero values take the defaults above;
// the header timeout and header size cannot be disabled, only overridden.
type HTTPOptions struct {
	Addr    string
	Handler http.Handler

	// ReadTimeout covers the whole request read including the body. Services
	// that accept large uploads or proxy long requests raise it.
	ReadTimeout time.Duration
	// WriteTimeout covers the response write. Services that hold long-lived
	// (non-hijacked) responses raise it; hijacked WebSocket connections are
	// not subject to it.
	WriteTimeout time.Duration
	// IdleTimeout is how long a keep-alive connection may sit between requests.
	IdleTimeout time.Duration

	// ReadHeaderTimeout, MaxHeaderBytes and MaxConcurrentStreams override the
	// hardened defaults. There is no value that turns them off.
	ReadHeaderTimeout    time.Duration
	MaxHeaderBytes       int
	MaxConcurrentStreams int
}

// NewHTTP builds an http.Server with the hardened floor applied. It is the only
// way a service should construct its listener; cmd/*/main.go call it.
func NewHTTP(o HTTPOptions) *http.Server {
	pick := func(v, def time.Duration) time.Duration {
		if v <= 0 {
			return def
		}
		return v
	}
	headerBytes := o.MaxHeaderBytes
	if headerBytes <= 0 {
		headerBytes = DefaultMaxHeaderBytes
	}
	streams := o.MaxConcurrentStreams
	if streams <= 0 {
		streams = DefaultMaxConcurrentStreams
	}
	return &http.Server{
		Addr:              o.Addr,
		Handler:           o.Handler,
		ReadHeaderTimeout: pick(o.ReadHeaderTimeout, DefaultReadHeaderTimeout),
		ReadTimeout:       pick(o.ReadTimeout, DefaultReadTimeout),
		WriteTimeout:      pick(o.WriteTimeout, DefaultWriteTimeout),
		IdleTimeout:       pick(o.IdleTimeout, DefaultIdleTimeout),
		MaxHeaderBytes:    headerBytes,
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams: streams,
		},
	}
}
