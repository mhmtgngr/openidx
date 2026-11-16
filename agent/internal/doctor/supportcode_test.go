package doctor

import (
	"reflect"
	"strings"
	"testing"
)

func TestSupportCodeRoundTrip(t *testing.T) {
	b := Bundle{Checks: []Check{
		{ID: CheckDNS, Status: StatusFail, Code: CodeDNSFail, Detail: "idx.example.test"},
		{ID: CheckTunnel, Status: StatusWarn, Code: CodeTunnelOff},
		{ID: CheckHTTP, Status: StatusPass},
		{ID: CheckTCP, Status: StatusSkipped, Code: CodeTCPBlocked},
	}}
	code := SupportCode(b)
	if !strings.HasPrefix(code, "OX1-") || strings.Contains(code, "example") {
		t.Fatalf("code = %q", code)
	}
	got, err := DecodeSupportCode(code)
	if err != nil || !reflect.DeepEqual(got, []string{CodeDNSFail, CodeTunnelOff}) {
		t.Errorf("decoded %v, %v", got, err)
	}
	// As read over the phone: lower case, spaces, no dashes.
	spoken := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if got, err := DecodeSupportCode(spoken); err != nil || len(got) != 2 {
		t.Errorf("spoken form %q: %v, %v", spoken, got, err)
	}
}

func TestSupportCodeHealthyAndEveryCode(t *testing.T) {
	if got, err := DecodeSupportCode(SupportCode(Bundle{})); err != nil || len(got) != 0 {
		t.Errorf("healthy: %v, %v", got, err)
	}
	var all Bundle
	for _, c := range AllCodes {
		all.Checks = append(all.Checks, Check{Status: StatusFail, Code: c})
	}
	if got, err := DecodeSupportCode(SupportCode(all)); err != nil || !reflect.DeepEqual(got, AllCodes) {
		t.Errorf("all codes: %v, %v", got, err)
	}
}

func TestSupportCodeRefusesDamage(t *testing.T) {
	code := SupportCode(Bundle{Checks: []Check{{Status: StatusFail, Code: CodeTunnelDown}}})
	body := []byte(code)
	last := len(body) - 1
	if body[last] == 'A' {
		body[last] = 'B'
	} else {
		body[last] = 'A'
	}
	for _, bad := range []string{string(body), "", "hello", "OX1-", "ZZ9-ABCD", "OX1-0000"} {
		if _, err := DecodeSupportCode(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// Bit positions are the wire format: a code may be appended, never moved.
func TestAllCodesOrderIsPinned(t *testing.T) {
	pinned := []string{
		"CONFIG_UNREADABLE", "NOT_ENROLLED", "AUTH_INVALID", "DEVICE_REVOKED",
		"DNS_FAIL", "DNS_TIMEOUT", "TCP_BLOCKED", "TCP_TIMEOUT",
		"TLS_UNTRUSTED", "TLS_FAIL", "PROXY_AUTH_REQUIRED", "SERVER_HTTP_ERROR",
		"HTTP_TIMEOUT", "HTTP_FAIL", "CLOCK_SKEW", "IDENTITY_MISSING",
		"IDENTITY_EXPIRED", "IDENTITY_EXPIRING", "IDENTITY_INVALID",
		"SERVICE_NOT_RUNNING", "TUNNEL_DOWN", "TUNNEL_NOT_INSTALLED",
		"TUNNEL_OFF", "INTERNAL",
	}
	if len(AllCodes) < len(pinned) || !reflect.DeepEqual(AllCodes[:len(pinned)], pinned) {
		t.Error("AllCodes changed order: support codes already handed out would decode wrongly")
	}
}

func TestReportAndSummary(t *testing.T) {
	b := Bundle{
		Checks: []Check{
			{ID: CheckConfig, Status: StatusPass},
			{ID: CheckTunnel, Status: StatusFail, Code: CodeTunnelDown},
		},
		Repairs: []Repair{{ID: RepairRestartService, Outcome: OutcomeNeedsElevation}},
	}
	r := NewReport(b, LangTR)
	if r.Healthy || r.SupportCode != SupportCode(b) || len(r.Items) != 2 || len(r.Repairs) != 1 {
		t.Fatalf("report = %+v", r)
	}
	if r.Items[0].Title != "" || r.Items[1].Title != "Güvenli tünel çalışmıyor." || r.Items[1].Label != "Güvenli tünel" {
		t.Errorf("items = %+v", r.Items)
	}
	if r.Repairs[0].Result != "yönetici yetkisi gerekiyor" {
		t.Errorf("repairs = %+v", r.Repairs)
	}

	var sb strings.Builder
	Summary(&sb, b, LangEN)
	for _, want := range []string{"The secure tunnel is not working.", "→ ", "Support code", SupportCode(b)} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, sb.String())
		}
	}
	sb.Reset()
	Summary(&sb, Bundle{}, LangEN)
	if strings.TrimSpace(sb.String()) != "No problems found." {
		t.Errorf("healthy summary = %q", sb.String())
	}
}
