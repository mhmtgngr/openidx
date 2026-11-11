package transport

import (
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"strings"
)

var getenv = os.Getenv

// winHTTPProxy is the machine proxy configured with `netsh winhttp set proxy`,
// stored in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet
// Settings\Connections\WinHttpSettings. A service running as LocalSystem has
// no per-user IE settings, so this is the proxy an administrator sets for it.
type winHTTPProxy struct {
	// servers maps a scheme ("http", "https") to host:port; "" is the
	// catch-all entry of a plain "host:port" setting.
	servers map[string]string
	bypass  []string
}

// parseWinHTTPSettings decodes the WinHttpSettings REG_BINARY blob:
//
//	DWORD struct version (0x18 or 0x28)
//	DWORD change counter
//	DWORD flags (bit 0x2 = a named proxy is set; 0x1 alone is direct)
//	DWORD n, n bytes ASCII proxy list ("host:port" or "http=h:p;https=h:p")
//	DWORD m, m bytes ASCII bypass list ("<local>;*.corp;10.*")
//
// It returns nil, nil for a direct-access blob.
func parseWinHTTPSettings(b []byte) (*winHTTPProxy, error) {
	r := blobReader{b: b}
	if _, err := r.u32(); err != nil { // version
		return nil, err
	}
	if _, err := r.u32(); err != nil { // counter
		return nil, err
	}
	flags, err := r.u32()
	if err != nil {
		return nil, err
	}
	proxy, err := r.str()
	if err != nil {
		return nil, fmt.Errorf("proxy list: %w", err)
	}
	bypass, _ := r.str() // older blobs may end after the proxy list
	if flags&0x2 == 0 || strings.TrimSpace(proxy) == "" {
		return nil, nil
	}
	p := &winHTTPProxy{servers: map[string]string{}}
	for _, part := range strings.FieldsFunc(proxy, func(c rune) bool { return c == ';' || c == ' ' }) {
		if k, v, ok := strings.Cut(part, "="); ok {
			p.servers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		} else {
			p.servers[""] = strings.TrimSpace(part)
		}
	}
	for _, e := range strings.FieldsFunc(bypass, func(c rune) bool { return c == ';' || c == ' ' }) {
		p.bypass = append(p.bypass, strings.ToLower(strings.TrimSpace(e)))
	}
	return p, nil
}

// proxyFor picks the proxy for u, or nil when u is bypassed or none applies.
func (p *winHTTPProxy) proxyFor(u *url.URL) *url.URL {
	host := strings.ToLower(u.Hostname())
	for _, b := range p.bypass {
		switch {
		case b == "<local>":
			if !strings.Contains(host, ".") {
				return nil
			}
		case strings.HasPrefix(b, "*"):
			if strings.HasSuffix(host, b[1:]) {
				return nil
			}
		case strings.HasSuffix(b, "*"):
			if strings.HasPrefix(host, b[:len(b)-1]) {
				return nil
			}
		case b == host:
			return nil
		}
	}
	s, ok := p.servers[strings.ToLower(u.Scheme)]
	if !ok {
		s, ok = p.servers[""]
	}
	if !ok || s == "" {
		return nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	pu, err := url.Parse(s)
	if err != nil || pu.Host == "" {
		return nil
	}
	return pu
}

type blobReader struct {
	b   []byte
	off int
}

func (r *blobReader) u32() (uint32, error) {
	if r.off+4 > len(r.b) {
		return 0, fmt.Errorf("WinHttpSettings blob truncated at offset %d", r.off)
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, nil
}

func (r *blobReader) str() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	if n > uint32(len(r.b)-r.off) {
		return "", fmt.Errorf("WinHttpSettings string length %d overruns blob", n)
	}
	s := string(r.b[r.off : r.off+int(n)])
	r.off += int(n)
	return s, nil
}
