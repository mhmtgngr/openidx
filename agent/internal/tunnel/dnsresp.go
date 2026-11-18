package tunnel

import (
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Responder is the small DNS server the agent runs on loopback for the names it
// pins (names.go). It answers an A question for a name in its table with that
// name's address, answers any other question about such a name with "no data",
// and REFUSES everything else. It forwards nothing and recurses nothing, so it
// is not an open resolver and it cannot be made to ask anyone anything.
type Responder struct {
	table    atomic.Pointer[map[string][4]byte]
	answered atomic.Uint64
}

// DNS wire constants the responder uses.
const (
	dnsTypeA    = 1
	dnsClassIN  = 1
	rcodeOK     = 0
	rcodeFormat = 1
	rcodeNotImp = 4
	rcodeRefuse = 5

	// maxDNSName is the longest name the protocol allows (RFC 1035).
	maxDNSName = 253
	// answerTTL is short on purpose: a pin that moves must not be remembered.
	answerTTL = 30
)

// SetTable replaces what the responder answers. Keys are lower-case names
// without a trailing dot.
func (r *Responder) SetTable(pins map[string][4]byte) {
	cp := make(map[string][4]byte, len(pins))
	for k, v := range pins {
		cp[strings.ToLower(strings.TrimSuffix(k, "."))] = v
	}
	r.table.Store(&cp)
}

// Answered counts the questions answered from the table, as opposed to refused.
// The self-test uses it to tell an answer from this responder from a cached one.
func (r *Responder) Answered() uint64 { return r.answered.Load() }

// Answer returns the reply to one DNS message, or nil when the message is not
// one to reply to (too short, or itself a reply). It never panics on garbage.
func (r *Responder) Answer(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	flags := uint16(q[2])<<8 | uint16(q[3])
	if flags&0x8000 != 0 {
		return nil // a response: answering it would be a reflection loop
	}
	header := func(rcode int, qd, an int, authoritative bool) []byte {
		f := uint16(0x8000) | (flags & 0x7800) | (flags & 0x0100) | uint16(rcode)
		if authoritative {
			f |= 0x0400
		}
		return []byte{q[0], q[1], byte(f >> 8), byte(f), byte(qd >> 8), byte(qd), byte(an >> 8), byte(an), 0, 0, 0, 0}
	}
	if uint16(q[4])<<8|uint16(q[5]) != 1 {
		return header(rcodeFormat, 0, 0, false)
	}
	name, end, ok := parseQuestionName(q, 12)
	if !ok || end+4 > len(q) {
		return header(rcodeFormat, 0, 0, false)
	}
	qtype := uint16(q[end])<<8 | uint16(q[end+1])
	qclass := uint16(q[end+2])<<8 | uint16(q[end+3])
	question := q[12 : end+4]

	if opcode := (flags >> 11) & 0xf; opcode != 0 {
		return append(header(rcodeNotImp, 1, 0, false), question...)
	}
	var addr [4]byte
	var found bool
	if t := r.table.Load(); t != nil {
		addr, found = (*t)[name]
	}
	if !found || qclass != dnsClassIN {
		return append(header(rcodeRefuse, 1, 0, false), question...)
	}
	r.answered.Add(1)
	if qtype != dnsTypeA {
		// The name exists, it just has no record of that type (AAAA, for one).
		return append(header(rcodeOK, 1, 0, true), question...)
	}
	resp := append(header(rcodeOK, 1, 1, true), question...)
	resp = append(resp, 0xc0, 0x0c, 0, dnsTypeA, 0, dnsClassIN, 0, 0, 0, answerTTL, 0, 4)
	return append(resp, addr[:]...)
}

// parseQuestionName reads a name at off. A name made of anything but plain
// labels (a compression pointer, a label over 63 bytes, a name over 253) is
// refused: a question has no business using them.
func parseQuestionName(q []byte, off int) (name string, end int, ok bool) {
	var b strings.Builder
	for {
		if off >= len(q) {
			return "", 0, false
		}
		l := int(q[off])
		if l == 0 {
			return strings.ToLower(b.String()), off + 1, b.Len() <= maxDNSName
		}
		if l&0xc0 != 0 || l > 63 || off+1+l > len(q) {
			return "", 0, false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(q[off+1 : off+1+l])
		if b.Len() > maxDNSName {
			return "", 0, false
		}
		off += 1 + l
	}
}

// ServeUDP answers datagrams on pc until it is closed.
func (r *Responder) ServeUDP(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := r.Answer(buf[:n]); resp != nil {
			_, _ = pc.WriteTo(resp, addr)
		}
	}
}

// maxTCPClients bounds the connections served at once: on loopback this is a
// handful of resolvers, never a crowd.
const maxTCPClients = 16

// ServeTCP answers length-prefixed messages on connections from l until it is
// closed.
func (r *Responder) ServeTCP(l net.Listener) {
	sem := make(chan struct{}, maxTCPClients)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer c.Close()
			r.serveConn(c)
		}()
	}
}

func (r *Responder) serveConn(c net.Conn) {
	for i := 0; i < 4; i++ {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var lenb [2]byte
		if _, err := io.ReadFull(c, lenb[:]); err != nil {
			return
		}
		n := int(lenb[0])<<8 | int(lenb[1])
		if n < 12 || n > 1500 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		resp := r.Answer(msg)
		if resp == nil {
			return
		}
		if _, err := c.Write(append([]byte{byte(len(resp) >> 8), byte(len(resp))}, resp...)); err != nil {
			return
		}
	}
}
