package doctor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openidx/openidx/agent/internal/tunnel"
)

var testNow = time.Date(2026, 11, 16, 14, 2, 0, 0, time.UTC)

const testServer = "https://idx.example.test"

// fakeProbes answers from fields; the zero value is a healthy network.
type fakeProbes struct {
	resolveErr error
	noAddrs    bool
	dialErr    error
	dialBlocks bool
	tlsErr     error
	httpStatus int
	httpErr    error
	httpDate   time.Time
	proxy      *url.URL
	panicHTTP  bool
}

func (f fakeProbes) Resolve(context.Context, string) ([]string, error) {
	if f.resolveErr != nil || f.noAddrs {
		return nil, f.resolveErr
	}
	return []string{"198.51.100.7"}, nil
}

func (f fakeProbes) DialTCP(ctx context.Context, _ string) error {
	if f.dialBlocks {
		<-ctx.Done()
		return ctx.Err()
	}
	return f.dialErr
}

func (f fakeProbes) TLSHandshake(context.Context, string, string) error { return f.tlsErr }

func (f fakeProbes) HTTPGet(context.Context, string) (HTTPResult, error) {
	if f.panicHTTP {
		panic("boom")
	}
	if f.httpErr != nil {
		return HTTPResult{}, f.httpErr
	}
	st, d := f.httpStatus, f.httpDate
	if st == 0 {
		st = 401
	}
	if d.IsZero() {
		d = testNow
	}
	return HTTPResult{Status: st, Date: d}, nil
}

func (f fakeProbes) Proxy(string) *url.URL { return f.proxy }
func (f fakeProbes) Now() time.Time        { return testNow }

func healthyInputs() Inputs {
	running := true
	return Inputs{
		AgentID: "agent-1", AgentVersion: "0.6.0", ServerURL: testServer,
		Enrolled: true, TunnelExpected: true, ServiceRunning: &running,
		Tunnel: &tunnel.Status{State: tunnel.StateConnected, Services: []string{"a", "b"}},
	}
}

func byID(t *testing.T, b Bundle, id string) Check {
	t.Helper()
	for _, c := range b.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("bundle has no %q check", id)
	return Check{}
}

func wantCheck(t *testing.T, b Bundle, id string, status CheckStatus, code string) {
	t.Helper()
	if c := byID(t, b, id); c.Status != status || c.Code != code {
		t.Errorf("%s = %s/%q, want %s/%q", id, c.Status, c.Code, status, code)
	}
}

func assertOrder(t *testing.T, b Bundle) {
	t.Helper()
	if len(b.Checks) != len(CheckOrder) {
		t.Fatalf("bundle has %d checks, want %d: %+v", len(b.Checks), len(CheckOrder), b.Checks)
	}
	for i, id := range CheckOrder {
		if b.Checks[i].ID != id {
			t.Fatalf("check %d is %q, want %q", i, b.Checks[i].ID, id)
		}
	}
}

func TestRunHealthy(t *testing.T) {
	b := Run(context.Background(), healthyInputs(), fakeProbes{}, Options{})
	assertOrder(t, b)
	if !b.Healthy() {
		t.Fatalf("healthy inputs failed: %+v", b.Failing())
	}
	if b.Schema != SchemaVersion || !b.Net.DNSOK || b.Net.ProxyMode != "none" {
		t.Errorf("unexpected bundle header: %+v", b)
	}
	if b.ClockSkewS == nil || *b.ClockSkewS != 0 {
		t.Errorf("clock skew = %v, want 0", b.ClockSkewS)
	}
}

// Review focus 1: a device that was never enrolled.
func TestRunNotEnrolledSkipsServerChecks(t *testing.T) {
	b := Run(context.Background(), Inputs{}, fakeProbes{}, Options{})
	assertOrder(t, b)
	wantCheck(t, b, CheckConfig, StatusFail, CodeNotEnrolled)
	for _, id := range []string{CheckDNS, CheckTCP, CheckTLS, CheckHTTP, CheckClock} {
		wantCheck(t, b, id, StatusSkipped, "")
	}
	if b.Healthy() {
		t.Error("an unenrolled device must not be healthy")
	}
}

func TestRunSkipChain(t *testing.T) {
	deadline := context.DeadlineExceeded
	cases := []struct {
		name   string
		probes fakeProbes
		want   map[string][2]string // id → status, code
	}{
		{"dns fail skips tcp and tls, http still runs", fakeProbes{resolveErr: errors.New("nxdomain")},
			map[string][2]string{CheckDNS: {"fail", CodeDNSFail}, CheckTCP: {"skipped", ""}, CheckTLS: {"skipped", ""}, CheckHTTP: {"pass", ""}}},
		{"dns no addresses", fakeProbes{noAddrs: true}, map[string][2]string{CheckDNS: {"fail", CodeDNSFail}}},
		{"dns timeout", fakeProbes{resolveErr: deadline}, map[string][2]string{CheckDNS: {"fail", CodeDNSTimeout}}},
		{"tcp refused skips tls", fakeProbes{dialErr: errors.New("refused")},
			map[string][2]string{CheckTCP: {"fail", CodeTCPBlocked}, CheckTLS: {"skipped", ""}}},
		{"tls untrusted", fakeProbes{tlsErr: x509.UnknownAuthorityError{}}, map[string][2]string{CheckTLS: {"fail", CodeTLSUntrusted}}},
		{"tls hostname", fakeProbes{tlsErr: x509.HostnameError{Host: "x"}}, map[string][2]string{CheckTLS: {"fail", CodeTLSUntrusted}}},
		{"tls other", fakeProbes{tlsErr: errors.New("eof")}, map[string][2]string{CheckTLS: {"fail", CodeTLSFail}}},
		{"proxy auth", fakeProbes{httpStatus: 407}, map[string][2]string{CheckHTTP: {"fail", CodeProxyAuthRequired}}},
		{"server error", fakeProbes{httpStatus: 503}, map[string][2]string{CheckHTTP: {"fail", CodeServerHTTPError}}},
		{"http timeout", fakeProbes{httpErr: deadline}, map[string][2]string{CheckHTTP: {"fail", CodeHTTPTimeout}, CheckClock: {"skipped", ""}}},
		{"http down", fakeProbes{httpErr: errors.New("reset")}, map[string][2]string{CheckHTTP: {"fail", CodeHTTPFail}}},
		{"clock ahead", fakeProbes{httpDate: testNow.Add(-6 * time.Minute)}, map[string][2]string{CheckClock: {"fail", CodeClockSkew}}},
		{"clock behind", fakeProbes{httpDate: testNow.Add(6 * time.Minute)}, map[string][2]string{CheckClock: {"fail", CodeClockSkew}}},
		{"clock within limit", fakeProbes{httpDate: testNow.Add(4 * time.Minute)}, map[string][2]string{CheckClock: {"pass", ""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := Run(context.Background(), healthyInputs(), tc.probes, Options{})
			assertOrder(t, b)
			for id, w := range tc.want {
				wantCheck(t, b, id, CheckStatus(w[0]), w[1])
			}
		})
	}
}

// Review focus 4: a probe that hangs must not stall the rest.
func TestRunHungProbeDoesNotBlockLaterChecks(t *testing.T) {
	old := probeTimeout
	probeTimeout = 20 * time.Millisecond
	defer func() { probeTimeout = old }()

	start := time.Now()
	b := Run(context.Background(), healthyInputs(), fakeProbes{dialBlocks: true}, Options{})
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("run took %v with a hung dial", took)
	}
	assertOrder(t, b)
	wantCheck(t, b, CheckTCP, StatusFail, CodeTCPTimeout)
	wantCheck(t, b, CheckHTTP, StatusPass, "")
	wantCheck(t, b, CheckTunnel, StatusPass, "")
}

func TestRunRecoversCheckPanic(t *testing.T) {
	b := Run(context.Background(), healthyInputs(), fakeProbes{panicHTTP: true}, Options{})
	assertOrder(t, b)
	wantCheck(t, b, CheckHTTP, StatusFail, CodeInternal)
	wantCheck(t, b, CheckTunnel, StatusPass, "")
}

// Review focus 5: an IP literal, and a non-default port.
func TestParseServer(t *testing.T) {
	cases := []struct {
		in, hostport string
		isIP, bad    bool
	}{
		{"https://idx.example.test", "idx.example.test:443", false, false},
		{"https://idx.example.test:8443/", "idx.example.test:8443", false, false},
		{"https://198.51.100.7", "198.51.100.7:443", true, false},
		{"http://idx.example.test", "idx.example.test:80", false, false},
		{"idx.example.test", "", false, true},
		{"ftp://idx.example.test", "", false, true},
	}
	for _, tc := range cases {
		got, err := parseServer(tc.in)
		if (err != nil) != tc.bad {
			t.Errorf("parseServer(%q) error = %v, want error %v", tc.in, err, tc.bad)
			continue
		}
		if !tc.bad && (got.HostPort != tc.hostport || got.IsIP != tc.isIP) {
			t.Errorf("parseServer(%q) = %+v", tc.in, got)
		}
	}
}

func TestIPLiteralSkipsDNS(t *testing.T) {
	in := healthyInputs()
	in.ServerURL = "https://198.51.100.7:8443"
	b := Run(context.Background(), in, fakeProbes{resolveErr: errors.New("must not be asked")}, Options{})
	wantCheck(t, b, CheckDNS, StatusSkipped, "")
	wantCheck(t, b, CheckTCP, StatusPass, "")
	if !b.Net.DNSOK {
		t.Error("a skipped lookup is not a DNS failure")
	}
}

// Review focus 3: proxy credentials never reach the bundle or the text.
func TestProxyCredentialsNeverLeak(t *testing.T) {
	const secret = "hunter2-fixture"
	proxy, _ := url.Parse("http://alice:" + secret + "@proxy.example.test:8080")
	in := healthyInputs()
	in.ProxyURL = proxy.String()
	b := Run(context.Background(), in, fakeProbes{proxy: proxy, dialErr: errors.New("direct dial is blocked")}, Options{})

	if b.Net.ProxyMode != "configured" || b.Net.ProxyHost != "proxy.example.test:8080" {
		t.Errorf("net = %+v", b.Net)
	}
	for _, id := range []string{CheckDNS, CheckTCP, CheckTLS} {
		wantCheck(t, b, id, StatusSkipped, "")
	}
	if !b.Healthy() {
		t.Errorf("behind a working proxy the direct dial must not count: %+v", b.Failing())
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	Render(&text, b, LangEN)
	if strings.Contains(string(raw), secret) || strings.Contains(text.String(), secret) ||
		strings.Contains(string(raw), "alice") {
		t.Error("proxy credentials leaked into the output")
	}
}

func TestLocalChecks(t *testing.T) {
	no := false
	cases := []struct {
		name   string
		mutate func(*Inputs)
		id     string
		status CheckStatus
		code   string
	}{
		{"config unreadable", func(in *Inputs) { in.ConfigErr = fs.ErrPermission; in.Enrolled = false }, CheckConfig, StatusFail, CodeConfigUnreadable},
		{"revoked wins over auth invalid", func(in *Inputs) { in.Revoked, in.AuthInvalid = true, true }, CheckCredentials, StatusFail, CodeDeviceRevoked},
		{"auth invalid", func(in *Inputs) { in.AuthInvalid = true }, CheckCredentials, StatusFail, CodeAuthInvalid},
		{"service down", func(in *Inputs) { in.ServiceRunning = &no }, CheckService, StatusFail, CodeServiceNotRunning},
		{"service unknown", func(in *Inputs) { in.ServiceRunning = nil }, CheckService, StatusSkipped, ""},
		{"tunnel degraded", func(in *Inputs) { in.Tunnel = &tunnel.Status{State: tunnel.StateDegraded} }, CheckTunnel, StatusFail, CodeTunnelDown},
		{"tunnel not installed", func(in *Inputs) { in.Tunnel = &tunnel.Status{State: tunnel.StateNotInstalled} }, CheckTunnel, StatusFail, CodeTunnelNotInstalled},
		{"tunnel enabled but off", func(in *Inputs) { in.Tunnel = &tunnel.Status{State: tunnel.StateOff} }, CheckTunnel, StatusFail, CodeTunnelDown},
		{"tunnel unknown", func(in *Inputs) { in.Tunnel = nil }, CheckTunnel, StatusSkipped, ""},
		{"tunnel not in use", func(in *Inputs) { in.TunnelExpected, in.Tunnel = false, nil }, CheckTunnel, StatusWarn, CodeTunnelOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := healthyInputs()
			tc.mutate(&in)
			b := Run(context.Background(), in, fakeProbes{}, Options{})
			wantCheck(t, b, tc.id, tc.status, tc.code)
		})
	}
}

func TestTunnelDetailIsClipped(t *testing.T) {
	in := healthyInputs()
	in.Tunnel = &tunnel.Status{State: tunnel.StateDegraded, LastError: strings.Repeat("ğ", 5000)}
	if got := len([]rune(checkTunnel(in).Detail)); got != maxDetail {
		t.Errorf("detail is %d runes, want %d", got, maxDetail)
	}
}

func identityJSON(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dev-agent-1"},
		NotBefore: testNow.Add(-24 * time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	doc := map[string]any{"ztAPI": "https://ctrl.example.test:1280", "id": map[string]string{
		"cert": "pem:" + string(certPEM),
		"key":  "pem:-----BEGIN EC PRIVATE KEY-----\nfixture\n-----END EC PRIVATE KEY-----\n",
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCheckIdentity(t *testing.T) {
	read := func(data []byte, err error) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return data, err }
	}
	cases := []struct {
		name   string
		file   string
		read   func(string) ([]byte, error)
		status CheckStatus
		code   string
	}{
		{"none expected", "", read(nil, nil), StatusSkipped, ""},
		{"valid", "id.json", read(identityJSON(t, testNow.Add(365*24*time.Hour)), nil), StatusPass, ""},
		{"expiring", "id.json", read(identityJSON(t, testNow.Add(3*24*time.Hour)), nil), StatusWarn, CodeIdentityExpiring},
		{"expired", "id.json", read(identityJSON(t, testNow.Add(-time.Hour)), nil), StatusFail, CodeIdentityExpired},
		{"missing", "id.json", read(nil, fs.ErrNotExist), StatusFail, CodeIdentityMissing},
		{"no permission", "id.json", read(nil, fs.ErrPermission), StatusSkipped, ""},
		{"garbage", "id.json", read([]byte("not json"), nil), StatusFail, CodeIdentityInvalid},
		{"no certificate", "id.json", read([]byte(`{"id":{"cert":"pem:"}}`), nil), StatusFail, CodeIdentityInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, notAfter := checkIdentity(Inputs{IdentityFile: tc.file}, tc.read, testNow)
			if c.Status != tc.status || c.Code != tc.code {
				t.Errorf("got %s/%q, want %s/%q", c.Status, c.Code, tc.status, tc.code)
			}
			if strings.Contains(c.Detail, "PRIVATE KEY") {
				t.Error("key material in the check detail")
			}
			if (tc.status == StatusPass || tc.code == CodeIdentityExpired) && notAfter == nil {
				t.Error("expiry not reported")
			}
		})
	}
}

func TestBundleJSONShape(t *testing.T) {
	raw, err := json.Marshal(Bundle{Schema: SchemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema":1`, `"checks":[]`, `"repairs":[]`, `"enrollment":{`, `"net":{`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("bundle JSON lacks %s: %s", want, raw)
		}
	}
	var back Bundle
	b := Run(context.Background(), healthyInputs(), fakeProbes{}, Options{})
	raw, _ = json.Marshal(b)
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Checks) != len(CheckOrder) {
		t.Errorf("bundle does not round-trip: %v", err)
	}
}

type fakeActions struct {
	flushErr, restartErr error
	calls                []string
}

func (f *fakeActions) FlushDNS(context.Context) error {
	f.calls = append(f.calls, RepairFlushDNS)
	return f.flushErr
}

func (f *fakeActions) RestartService(context.Context) error {
	f.calls = append(f.calls, RepairRestartService)
	return f.restartErr
}

func bundleWith(codes ...string) Bundle {
	b := Bundle{}
	for _, c := range codes {
		b.Checks = append(b.Checks, Check{ID: "x", Status: StatusFail, Code: c})
	}
	return b
}

func TestPlanRepairs(t *testing.T) {
	cases := []struct {
		codes []string
		want  []string
	}{
		{nil, nil},
		{[]string{CodeClockSkew, CodeNotEnrolled, CodeTLSUntrusted}, nil},
		{[]string{CodeDNSFail}, []string{RepairFlushDNS}},
		{[]string{CodeTunnelDown, CodeServiceNotRunning}, []string{RepairRestartService}},
		{[]string{CodeTunnelDown, CodeDNSTimeout}, []string{RepairFlushDNS, RepairRestartService}},
	}
	for _, tc := range cases {
		got := PlanRepairs(bundleWith(tc.codes...))
		if len(got) != len(tc.want) {
			t.Errorf("%v: planned %+v, want %v", tc.codes, got, tc.want)
			continue
		}
		for i := range got {
			if got[i].ID != tc.want[i] || got[i].Outcome != OutcomePlanned {
				t.Errorf("%v: repair %d = %+v", tc.codes, i, got[i])
			}
		}
	}
}

func TestApplyRepairsContinuesAfterFailure(t *testing.T) {
	a := &fakeActions{flushErr: ErrUnsupported, restartErr: ErrNeedsElevation}
	got := ApplyRepairs(context.Background(), bundleWith(CodeDNSFail, CodeTunnelDown), a)
	if len(a.calls) != 2 || len(got) != 2 {
		t.Fatalf("calls %v, repairs %+v", a.calls, got)
	}
	if got[0].Outcome != OutcomeFailed || got[1].Outcome != OutcomeNeedsElevation {
		t.Errorf("outcomes = %+v", got)
	}
	a = &fakeActions{}
	if got := ApplyRepairs(context.Background(), bundleWith(CodeTunnelDown), a); got[0].Outcome != OutcomeApplied {
		t.Errorf("outcome = %+v", got)
	}
}

func TestEveryCodeAndLabelHasBothLanguages(t *testing.T) {
	en, tr := tables[LangEN], tables[LangTR]
	for _, code := range AllCodes {
		e, ok1 := en.codes[code]
		r, ok2 := tr.codes[code]
		if !ok1 || !ok2 || e.Title == "" || e.Action == "" || r.Title == "" || r.Action == "" {
			t.Errorf("code %s lacks text in en or tr", code)
		}
		if e.Title == r.Title {
			t.Errorf("code %s is not translated", code)
		}
	}
	if len(en.codes) != len(AllCodes) || len(tr.codes) != len(AllCodes) {
		t.Error("a string table names a code AllCodes does not")
	}
	for _, id := range CheckOrder {
		if en.checks[id] == "" || tr.checks[id] == "" {
			t.Errorf("check %s lacks a label", id)
		}
	}
	for _, id := range []string{RepairFlushDNS, RepairRestartService} {
		if en.repairs[id] == "" || tr.repairs[id] == "" {
			t.Errorf("repair %s lacks a label", id)
		}
	}
	for _, o := range []string{OutcomePlanned, OutcomeApplied, OutcomeFailed, OutcomeNeedsElevation} {
		if en.outcomes[o] == "" || tr.outcomes[o] == "" {
			t.Errorf("outcome %s lacks a label", o)
		}
	}
}

func TestRender(t *testing.T) {
	var out bytes.Buffer
	Render(&out, Run(context.Background(), healthyInputs(), fakeProbes{}, Options{}), LangEN)
	if !strings.Contains(out.String(), "No problems found.") {
		t.Errorf("healthy output:\n%s", out.String())
	}

	in := healthyInputs()
	in.Tunnel = &tunnel.Status{State: tunnel.StateDegraded}
	b := Run(context.Background(), in, fakeProbes{}, Options{})
	b.Repairs = PlanRepairs(b)
	out.Reset()
	Render(&out, b, LangTR)
	got := out.String()
	for _, want := range []string{
		"OpenIDX bağlantı teşhisi — 2026-11-16 14:02 UTC",
		"✗ Güvenli tünel", "TUNNEL_DOWN",
		"Sorun: Güvenli tünel çalışmıyor.",
		"Ne yapmalı: ",
		"Onarım: Ajan servisini yeniden başlat — --fix ile denenir",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Turkish output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Sorun bulunmadı.") {
		t.Error("a failing bundle must not say all is well")
	}
}

func TestParseLang(t *testing.T) {
	if l, err := ParseLang("tr"); err != nil || l != LangTR {
		t.Errorf("tr → %v, %v", l, err)
	}
	if _, err := ParseLang("de"); err == nil {
		t.Error("an unknown language must be refused")
	}
}
