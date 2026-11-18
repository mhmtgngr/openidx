package doctor

import (
	"bytes"
	"context"
	"testing"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

func connected() *tunnel.Status { return &tunnel.Status{State: tunnel.StateConnected} }

func TestNamesCheckWarnsWhenAnAddressNobodyOwnsAnswers(t *testing.T) {
	c := checkNames(context.Background(), fakeProbes{dnsAnswers: true}, Inputs{Tunnel: connected()})
	if c.Status != StatusWarn || c.Code != CodeDNSIntercepted {
		t.Fatalf("got %s/%s, want warn/%s", c.Status, c.Code, CodeDNSIntercepted)
	}
	if c.ID != CheckNames {
		t.Errorf("id %q, want %q", c.ID, CheckNames)
	}
}

func TestNamesCheckPassesWhenNothingAnswers(t *testing.T) {
	c := checkNames(context.Background(), fakeProbes{}, Inputs{Tunnel: connected()})
	if c.Status != StatusPass || c.Code != "" {
		t.Fatalf("a clean device (no answer) got %s/%s, want pass", c.Status, c.Code)
	}
}

func TestNamesCheckPassesWhenTheAgentAnswersTheNamesItself(t *testing.T) {
	// Another program answers the tunneler's DNS, and the agent answers the names
	// of tunneled applications itself, so the interception no longer matters.
	c := checkNames(context.Background(), fakeProbes{dnsAnswers: true}, Inputs{Tunnel: connected(), NamesByAgent: true})
	if c.Status != StatusPass || c.Code != "" {
		t.Fatalf("got %s/%s, want pass", c.Status, c.Code)
	}
	// Without it the same device is a finding.
	c = checkNames(context.Background(), fakeProbes{dnsAnswers: true}, Inputs{Tunnel: connected()})
	if c.Status != StatusWarn {
		t.Fatalf("got %s, want warn", c.Status)
	}
}

func TestNamesCheckIsSkippedWithoutAConnectedTunnel(t *testing.T) {
	cases := map[string]Inputs{
		"no tunnel status": {},
		"tunnel off":       {Tunnel: &tunnel.Status{State: tunnel.StateOff}},
		"tunnel degraded":  {Tunnel: &tunnel.Status{State: tunnel.StateDegraded}},
		"not installed":    {Tunnel: &tunnel.Status{State: tunnel.StateNotInstalled}},
		"phone":            {Tunnel: connected(), Mobile: true},
	}
	for name, in := range cases {
		// An answering address would be a finding, so a skip must not even ask.
		c := checkNames(context.Background(), fakeProbes{dnsAnswers: true}, in)
		if c.Status != StatusSkipped {
			t.Errorf("%s: got %s, want skipped", name, c.Status)
		}
	}
}

func TestRunListsTheNamesCheckLastAndCountsItInTheSupportCode(t *testing.T) {
	in := Inputs{Tunnel: connected()}
	b := Run(context.Background(), in, fakeProbes{dnsAnswers: true}, Options{})
	last := b.Checks[len(b.Checks)-1]
	if last.ID != CheckNames || last.Code != CodeDNSIntercepted {
		t.Fatalf("last check is %s/%s, want %s/%s", last.ID, last.Code, CheckNames, CodeDNSIntercepted)
	}
	codes, err := DecodeSupportCode(SupportCode(b))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range codes {
		found = found || c == CodeDNSIntercepted
	}
	if !found {
		t.Errorf("support code names %v, want it to include %s", codes, CodeDNSIntercepted)
	}
}

// The probe is raw bytes, so pin them: a label's length byte must be the
// label's length (a hyphen is part of it), and the question must end with the
// root label, type A and class IN.
func TestBuildDNSQuery(t *testing.T) {
	got := buildDNSQuery(0x4f58, "es-dev.tdv.org")
	want := []byte{0x4f, 0x58, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	want = append(want, 6, 'e', 's', '-', 'd', 'e', 'v', 3, 't', 'd', 'v', 3, 'o', 'r', 'g', 0, 0, 1, 0, 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("query bytes\n got %v\nwant %v", got, want)
	}
	if !bytes.Equal(buildDNSQuery(1, "a.b."), buildDNSQuery(1, "a.b")) {
		t.Error("a trailing dot must not change the question")
	}
}

func TestParseDNSReply(t *testing.T) {
	reply := func(id uint16, flags2, flags3 byte, an byte) []byte {
		return []byte{byte(id >> 8), byte(id), flags2, flags3, 0, 1, 0, an, 0, 1, 0, 0}
	}
	got, err := parseDNSReply(0x4f58, reply(0x4f58, 0x81, 0x83, 0))
	if err != nil || got.RCode != 3 || got.Answers != 0 {
		t.Fatalf("NXDOMAIN reply: %+v, %v", got, err)
	}
	got, err = parseDNSReply(0x4f58, reply(0x4f58, 0x81, 0x80, 2))
	if err != nil || got.RCode != 0 || got.Answers != 2 {
		t.Fatalf("answer reply: %+v, %v", got, err)
	}
	for name, bad := range map[string][]byte{
		"short":                {1, 2, 3},
		"another query":        reply(0x1111, 0x81, 0x80, 0),
		"a query, not a reply": reply(0x4f58, 0x01, 0x00, 0),
	} {
		if _, err := parseDNSReply(0x4f58, bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
