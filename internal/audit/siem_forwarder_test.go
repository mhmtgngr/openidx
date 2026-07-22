package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sampleEvent() siemEvent {
	return siemEvent{
		ID:        "11111111-2222-3333-4444-555555555555",
		Timestamp: time.Date(2026, 7, 22, 10, 30, 0, 0, time.UTC),
		OrgID:     "org-abc",
		ActorID:   "user-42",
		ActorType: "user",
		ActorIP:   "203.0.113.9",
		TargetID:  "app-7",
		Target:    "application",
		EventType: "oauth.token.issued",
		Category:  "authentication",
		Action:    "token_issued",
		Outcome:   "success",
		Details:   json.RawMessage(`{"scope":"openid"}`),
	}
}

func TestFormatSyslog_RFC5424Shape(t *testing.T) {
	msg := formatSyslog("host1", sampleEvent())
	if !strings.HasPrefix(msg, "<") {
		t.Fatalf("syslog must start with PRI: %q", msg)
	}
	// PRI = local0(16)*8 + informational(6) = 134 for success.
	if !strings.HasPrefix(msg, "<134>1 ") {
		t.Errorf("expected <134>1 for success outcome, got %q", msg[:12])
	}
	for _, want := range []string{
		`event_id="11111111-2222-3333-4444-555555555555"`,
		`action="token_issued"`,
		`outcome="success"`,
		`actor_ip="203.0.113.9"`,
		"openidx@0",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("syslog missing %q in %q", want, msg)
		}
	}
	if !strings.HasSuffix(msg, "\n") {
		t.Error("syslog message must be newline-terminated")
	}
}

func TestFormatSyslog_FailureSeverity(t *testing.T) {
	e := sampleEvent()
	e.Outcome = "failure"
	msg := formatSyslog("h", e)
	// PRI = 16*8 + warning(4) = 132.
	if !strings.HasPrefix(msg, "<132>1 ") {
		t.Errorf("failure should raise severity (PRI 132), got %q", msg[:12])
	}
}

func TestFormatCEF_Shape(t *testing.T) {
	msg := formatCEF("host1", sampleEvent())
	if !strings.Contains(msg, "CEF:0|OpenIDX|OpenIDX|1|oauth.token.issued|token_issued|3|") {
		t.Errorf("CEF header malformed: %q", msg)
	}
	for _, want := range []string{"suser=user-42", "src=203.0.113.9", "outcome=success", "eventId=11111111"} {
		if !strings.Contains(msg, want) {
			t.Errorf("CEF missing %q in %q", want, msg)
		}
	}
}

func TestSDParam_Escaping(t *testing.T) {
	got := sdParam("k", `a"b\c]d`)
	want := ` k="a\"b\\c\]d"`
	if got != want {
		t.Errorf("sdParam escaping: got %q want %q", got, want)
	}
	if sdParam("k", "") != "" {
		t.Error("empty value must be omitted")
	}
}

// TestSyslogSink_DeliversFramedMessages stands up a TCP listener and asserts the
// sink writes octet-counted RFC 5424 frames for a batch.
func TestSyslogSink_DeliversFramedMessages(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		// Read the octet count, then that many bytes.
		var lenBuf []byte
		for {
			b, err := r.ReadByte()
			if err != nil {
				return
			}
			if b == ' ' {
				break
			}
			lenBuf = append(lenBuf, b)
		}
		n, _ := strconv.Atoi(string(lenBuf))
		payload := make([]byte, n)
		_, _ = io.ReadFull(r, payload)
		received <- string(payload)
	}()

	sink, err := newSyslogSink(SIEMConfig{Format: "syslog", Endpoint: ln.Addr().String(), Hostname: "h"})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.deliver([]siemEvent{sampleEvent()}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	select {
	case got := <-received:
		if !strings.Contains(got, `action="token_issued"`) {
			t.Errorf("framed payload missing action: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for syslog frame")
	}
}

// TestHECSink_PostsEnvelopes asserts the HEC sink POSTs newline-delimited JSON
// envelopes with the Splunk auth header.
func TestHECSink_PostsEnvelopes(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()

	sink := newHECSink(SIEMConfig{Format: "hec", Endpoint: srv.URL, Token: "TKN", Hostname: "h"})
	if err := sink.deliver([]siemEvent{sampleEvent()}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if gotAuth != "Splunk TKN" {
		t.Errorf("expected Splunk auth header, got %q", gotAuth)
	}
	var env hecEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(gotBody)), &env); err != nil {
		t.Fatalf("HEC body not valid envelope JSON: %v (%q)", err, gotBody)
	}
	if env.Sourcetype != "openidx:audit" {
		t.Errorf("sourcetype: got %q", env.Sourcetype)
	}
	ev, _ := env.Event.(map[string]interface{})
	if ev["action"] != "token_issued" {
		t.Errorf("HEC event action: got %v", ev["action"])
	}
}

// TestHECSink_Non2xxIsError ensures a rejecting HEC surfaces an error so the
// cursor doesn't advance.
func TestHECSink_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	sink := newHECSink(SIEMConfig{Endpoint: srv.URL, Token: "x"})
	if err := sink.deliver([]siemEvent{sampleEvent()}); err == nil {
		t.Error("expected error on non-2xx HEC response")
	}
}

func TestSIEMConfigFromEnv_Defaults(t *testing.T) {
	t.Setenv("AUDIT_SIEM_ENABLED", "true")
	t.Setenv("AUDIT_SIEM_ENDPOINT", "siem:514")
	t.Setenv("AUDIT_SIEM_FORMAT", "")
	c := SIEMConfigFromEnv()
	if !c.Enabled || c.Endpoint != "siem:514" {
		t.Fatalf("unexpected config: %+v", c)
	}
	if c.Format != "syslog" {
		t.Errorf("default format should be syslog, got %q", c.Format)
	}
	if c.PollInterval != 5*time.Second || c.BatchSize != 200 {
		t.Errorf("defaults: poll=%v batch=%d", c.PollInterval, c.BatchSize)
	}
}
