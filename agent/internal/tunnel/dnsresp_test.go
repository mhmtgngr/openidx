package tunnel

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// query builds a standard recursive question.
func query(id uint16, name string, qtype uint16) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func table(pairs ...string) map[string][4]byte {
	t := map[string][4]byte{}
	for i := 0; i < len(pairs); i += 2 {
		var a [4]byte
		copy(a[:], net.ParseIP(pairs[i+1]).To4())
		t[pairs[i]] = a
	}
	return t
}

func rcodeOf(r []byte) int { return int(r[3] & 0x0f) }
func ancount(r []byte) int { return int(r[6])<<8 | int(r[7]) }

func TestResponderAnswersAPinnedNameWithItsAddress(t *testing.T) {
	var r Responder
	r.SetTable(table("wiki.corp.example", "100.127.0.10"))
	resp := r.Answer(query(0x1234, "wiki.corp.example", dnsTypeA))
	if resp == nil || rcodeOf(resp) != 0 || ancount(resp) != 1 {
		t.Fatalf("reply = %v", resp)
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Error("the reply does not carry the question's id")
	}
	if resp[2]&0x80 == 0 || resp[2]&0x04 == 0 || resp[2]&0x01 == 0 {
		t.Errorf("flags %08b %08b: want QR, AA and the question's RD", resp[2], resp[3])
	}
	// The answer record: name pointer (2), type A (2), class IN (2), ttl (4), length 4 (2), address (4).
	tail := resp[len(resp)-16:]
	if !bytes.Equal(tail[:2], []byte{0xc0, 0x0c}) || !bytes.Equal(tail[2:6], []byte{0, 1, 0, 1}) ||
		!bytes.Equal(tail[10:12], []byte{0, 4}) || !bytes.Equal(tail[12:], []byte{100, 127, 0, 10}) {
		t.Errorf("answer record = % x", tail)
	}
	if ttl := binary.BigEndian.Uint32(tail[6:10]); ttl != answerTTL {
		t.Errorf("ttl = %d, want %d", ttl, answerTTL)
	}
	if r.Answered() != 1 {
		t.Errorf("answered = %d", r.Answered())
	}
}

func TestResponderIgnoresCaseAndATrailingDot(t *testing.T) {
	var r Responder
	r.SetTable(table("Wiki.Corp.Example.", "100.127.0.10"))
	for _, n := range []string{"wiki.corp.example", "WIKI.CORP.EXAMPLE", "Wiki.Corp.Example."} {
		if resp := r.Answer(query(1, n, dnsTypeA)); resp == nil || ancount(resp) != 1 {
			t.Errorf("%s was not answered", n)
		}
	}
}

func TestResponderSaysNoDataForOtherTypesAndRefusesStrangers(t *testing.T) {
	var r Responder
	r.SetTable(table("wiki.corp.example", "100.127.0.10"))
	// AAAA for a pinned name: it exists, there is no such record.
	if resp := r.Answer(query(1, "wiki.corp.example", 28)); resp == nil || rcodeOf(resp) != rcodeOK || ancount(resp) != 0 {
		t.Errorf("AAAA for a pinned name: %v", resp)
	}
	// A name that is not in the table is refused, never forwarded or guessed.
	for _, n := range []string{"example.com", "hr.corp.example", "corp.example", "100.127.0.10"} {
		resp := r.Answer(query(2, n, dnsTypeA))
		if resp == nil || rcodeOf(resp) != rcodeRefuse || ancount(resp) != 0 {
			t.Errorf("%s: reply %v, want REFUSED", n, resp)
		}
	}
	// Before any table is set, everything is refused.
	var empty Responder
	if resp := empty.Answer(query(3, "wiki.corp.example", dnsTypeA)); resp == nil || rcodeOf(resp) != rcodeRefuse {
		t.Errorf("an empty responder answered: %v", resp)
	}
	if r.Answered() != 1 {
		t.Errorf("only the pinned AAAA counts as answered, got %d", r.Answered())
	}
}

func TestResponderSurvivesGarbage(t *testing.T) {
	var r Responder
	r.SetTable(table("wiki.corp.example", "100.127.0.10"))
	good := query(7, "wiki.corp.example", dnsTypeA)
	cases := map[string][]byte{
		"empty":                   nil,
		"short":                   {1, 2, 3},
		"header only":             good[:12],
		"cut inside a label":      good[:15],
		"cut before the type":     good[:len(good)-4],
		"a compression pointer":   append(append([]byte{}, good[:12]...), 0xc0, 0x0c, 0, 1, 0, 1),
		"a 64-byte label":         append(append([]byte{}, good[:12]...), append([]byte{64}, bytes.Repeat([]byte{'a'}, 64)...)...),
		"two questions declared":  append([]byte{good[0], good[1], 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0}, good[12:]...),
		"zero questions declared": append([]byte{good[0], good[1], 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}, good[12:]...),
	}
	for name, msg := range cases {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s panicked: %v", name, p)
				}
			}()
			if resp := r.Answer(msg); resp != nil && rcodeOf(resp) == rcodeOK && ancount(resp) != 0 {
				t.Errorf("%s was answered with a record", name)
			}
		}()
	}
	// A reply is never answered (no reflection loop), and a non-query opcode is not implemented.
	reply := append([]byte{}, good...)
	reply[2] |= 0x80
	if r.Answer(reply) != nil {
		t.Error("a response was answered")
	}
	status := append([]byte{}, good...)
	status[2] |= 0x10 // opcode 2
	if resp := r.Answer(status); resp == nil || rcodeOf(resp) != rcodeNotImp {
		t.Errorf("opcode 2: %v", resp)
	}
	// A name over 253 bytes is refused.
	long := strings.Repeat("a.", 130) + "example"
	if resp := r.Answer(query(1, long, dnsTypeA)); resp == nil || rcodeOf(resp) != rcodeFormat {
		t.Errorf("a name over 253 bytes: %v", resp)
	}
}

func TestResponderServesUDPAndTCP(t *testing.T) {
	var r Responder
	r.SetTable(table("wiki.corp.example", "100.127.0.10"))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer pc.Close()
	go r.ServeUDP(pc)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer l.Close()
	go r.ServeTCP(l)

	u, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_ = u.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = u.Write(query(9, "wiki.corp.example", dnsTypeA))
	buf := make([]byte, 512)
	n, err := u.Read(buf)
	if err != nil || ancount(buf[:n]) != 1 {
		t.Fatalf("udp: %v, %v", buf[:n], err)
	}

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	for _, name := range []string{"wiki.corp.example", "other.example"} {
		q := query(10, name, dnsTypeA)
		_, _ = c.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...))
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			t.Fatalf("tcp %s: %v", name, err)
		}
		resp := make([]byte, int(lb[0])<<8|int(lb[1]))
		if _, err := io.ReadFull(c, resp); err != nil {
			t.Fatal(err)
		}
		want := rcodeOK
		if name != "wiki.corp.example" {
			want = rcodeRefuse
		}
		if rcodeOf(resp) != want {
			t.Errorf("tcp %s: rcode %d, want %d", name, rcodeOf(resp), want)
		}
	}
}
