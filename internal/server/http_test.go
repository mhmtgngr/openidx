package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTP_AppliesHardenedFloor(t *testing.T) {
	s := NewHTTP(HTTPOptions{Addr: ":0", Handler: http.NotFoundHandler()})
	assert.Equal(t, DefaultReadHeaderTimeout, s.ReadHeaderTimeout)
	assert.Equal(t, DefaultMaxHeaderBytes, s.MaxHeaderBytes)
	require.NotNil(t, s.HTTP2)
	assert.Equal(t, DefaultMaxConcurrentStreams, s.HTTP2.MaxConcurrentStreams)
	assert.Equal(t, DefaultReadTimeout, s.ReadTimeout)
	assert.Equal(t, DefaultWriteTimeout, s.WriteTimeout)
	assert.Equal(t, DefaultIdleTimeout, s.IdleTimeout)
}

func TestNewHTTP_PerServiceValuesOverrideOnlyWhatTheyName(t *testing.T) {
	s := NewHTTP(HTTPOptions{ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second})
	assert.Equal(t, 30*time.Second, s.ReadTimeout)
	assert.Equal(t, 60*time.Second, s.WriteTimeout)
	assert.Equal(t, 120*time.Second, s.IdleTimeout)
	// The floor is still there.
	assert.Equal(t, DefaultReadHeaderTimeout, s.ReadHeaderTimeout)
	assert.Equal(t, DefaultMaxHeaderBytes, s.MaxHeaderBytes)

	// Negative or zero never means "off".
	s = NewHTTP(HTTPOptions{ReadHeaderTimeout: -1, MaxHeaderBytes: 0, MaxConcurrentStreams: -5})
	assert.Equal(t, DefaultReadHeaderTimeout, s.ReadHeaderTimeout)
	assert.Equal(t, DefaultMaxHeaderBytes, s.MaxHeaderBytes)
	assert.Equal(t, DefaultMaxConcurrentStreams, s.HTTP2.MaxConcurrentStreams)
}

// A slowloris client opens a connection and never finishes its headers. The
// server must close it at ReadHeaderTimeout rather than hold it (and its
// goroutine, buffers and file descriptor) for as long as the attacker likes.
func TestNewHTTP_SlowHeadersAreCutAtReadHeaderTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := NewHTTP(HTTPOptions{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }),
		ReadHeaderTimeout: 300 * time.Millisecond,
		ReadTimeout:       10 * time.Second, // deliberately long: the header timeout must win
	})
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Request line, then trickle: never send the blank line that ends headers.
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
	require.NoError(t, err)

	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = bufio.NewReader(conn).ReadByte()
	elapsed := time.Since(start)

	require.Error(t, err, "server must close the half-sent request")
	assert.Less(t, elapsed, 3*time.Second, "closed by the header timeout, not by ReadTimeout or the test deadline")
}

// Oversized headers are refused with 431 before a handler ever runs; the size
// is bounded by MaxHeaderBytes, not by Go's 1 MiB default.
func TestNewHTTP_OversizedHeadersAreRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	handlerRan := false
	s := NewHTTP(HTTPOptions{
		Handler:        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlerRan = true }),
		MaxHeaderBytes: 4 << 10,
	})
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	big := strings.Repeat("a", 8<<10)
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nX-Big: "+big+"\r\n\r\n")
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	assert.Contains(t, line, "431", "request header fields too large")
	assert.False(t, handlerRan)
}
