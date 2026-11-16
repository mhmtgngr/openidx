package doctor

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/bundle_v1.json")

// The server keeps its own copy of the bundle types (the two modules cannot
// import each other) and decodes this same file strictly in
// internal/diagnose. A field added here without the server's copy fails
// there; a field renamed here fails here.
func TestBundleWireFormatV1(t *testing.T) {
	at := time.Date(2026, 11, 16, 14, 2, 0, 0, time.UTC)
	seen := at.Add(-time.Minute)
	expiry := at.Add(90 * 24 * time.Hour)
	skew := int64(-12)
	b := Bundle{
		Schema: SchemaVersion, AgentID: "agent-1", AgentVersion: "0.6.0", OS: "windows",
		CollectedAt: at, ClockSkewS: &skew,
		Checks: []Check{
			{ID: CheckConfig, Status: StatusPass, Millis: 1},
			{ID: CheckTunnel, Status: StatusFail, Code: CodeTunnelDown, Detail: "the tunneler exited", Millis: 3},
		},
		Repairs: []Repair{{ID: RepairRestartService, Outcome: OutcomeNeedsElevation, Detail: "x"}},
		Tunnel: &tunnel.Status{
			State: tunnel.StateDegraded, Version: "1.18.7", LastSeen: &seen, Services: []string{"svc-a"},
			Mode: "child", PolicyVersion: "p1", PolicyGaps: []string{"full_tunnel"}, LastError: "the tunneler exited",
		},
		Enrollment: Enrollment{Enrolled: true, AuthInvalid: true, Revoked: true, CertNotAfter: &expiry},
		Net:        Net{ProxyMode: "configured", ProxyHost: "proxy.example.test:8080", DNSOK: true},
	}
	got, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	const path = "testdata/bundle_v1.json"
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bundle wire format changed; if intended, bump SchemaVersion or update the server's copy, then run with -update.\ngot:\n%s", got)
	}
}

// The server decodes support codes with its own copy of the decoder
// (internal/diagnose) and checks it against this file.
func TestSupportCodeWireFormat(t *testing.T) {
	sets := [][]string{
		{},
		{CodeTunnelDown},
		{CodeDNSFail, CodeDNSTimeout},
		{CodeNotEnrolled},
		{CodeTLSUntrusted, CodeClockSkew, CodeTunnelOff},
		AllCodes,
	}
	got := map[string][]string{}
	for _, set := range sets {
		var b Bundle
		for _, c := range set {
			b.Checks = append(b.Checks, Check{Status: StatusFail, Code: c})
		}
		decoded, err := DecodeSupportCode(SupportCode(b))
		if err != nil {
			t.Fatal(err)
		}
		got[SupportCode(b)] = decoded
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	const path = "testdata/support_codes.json"
	if *updateGolden {
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Errorf("support code format changed; codes already handed out would decode wrongly.\ngot:\n%s", out)
	}
}
