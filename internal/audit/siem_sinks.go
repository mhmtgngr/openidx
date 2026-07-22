package audit

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─── syslog / CEF sink ──────────────────────────────────────────────────────

// syslogSink writes RFC 5424 syslog frames (optionally wrapping a CEF payload)
// over a persistent TCP (optionally TLS) connection using octet-counting framing
// (RFC 6587), which SIEMs parse unambiguously.
type syslogSink struct {
	cfg  SIEMConfig
	mu   sync.Mutex
	conn net.Conn
}

func newSyslogSink(cfg SIEMConfig) (*syslogSink, error) {
	s := &syslogSink{cfg: cfg}
	if err := s.dial(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *syslogSink) dial() error {
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if s.cfg.TLS {
		conn, err = tls.DialWithDialer(&d, "tcp", s.cfg.Endpoint, &tls.Config{
			InsecureSkipVerify: s.cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in for self-signed SIEMs
		})
	} else {
		conn, err = d.Dial("tcp", s.cfg.Endpoint)
	}
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *syslogSink) deliver(events []siemEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if err := s.dial(); err != nil {
			return err
		}
	}
	var buf bytes.Buffer
	for _, e := range events {
		var msg string
		if s.cfg.Format == "cef" {
			msg = formatCEF(s.cfg.Hostname, e)
		} else {
			msg = formatSyslog(s.cfg.Hostname, e)
		}
		// RFC 6587 octet-counting framing: "<len> <msg>".
		buf.WriteString(strconv.Itoa(len(msg)))
		buf.WriteByte(' ')
		buf.WriteString(msg)
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := s.conn.Write(buf.Bytes()); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *syslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// syslogFacilitySeverity: local0 (16) facility, severity by outcome. PRI = fac*8+sev.
func priFor(outcome string) int {
	const facility = 16 // local0
	sev := 6            // informational
	switch strings.ToLower(outcome) {
	case "failure", "denied", "error":
		sev = 4 // warning
	}
	return facility*8 + sev
}

// formatSyslog renders an event as an RFC 5424 message with a structured-data
// block carrying the audit fields. APP-NAME is "openidx", MSGID is the action.
func formatSyslog(hostname string, e siemEvent) string {
	ts := e.Timestamp.UTC().Format(time.RFC3339Nano)
	sd := "[openidx@0" +
		sdParam("event_id", e.ID) +
		sdParam("event_type", e.EventType) +
		sdParam("category", e.Category) +
		sdParam("action", e.Action) +
		sdParam("outcome", e.Outcome) +
		sdParam("org_id", e.OrgID) +
		sdParam("actor_id", e.ActorID) +
		sdParam("actor_type", e.ActorType) +
		sdParam("actor_ip", e.ActorIP) +
		sdParam("target_id", e.TargetID) +
		sdParam("target_type", e.Target) +
		"]"
	msgID := sanitizeToken(e.Action)
	if msgID == "" {
		msgID = "audit"
	}
	// VERSION=1, PROCID=-, human-readable MSG mirrors the key fields.
	human := fmt.Sprintf("%s %s by %s outcome=%s", e.Category, e.Action, e.ActorID, e.Outcome)
	return fmt.Sprintf("<%d>1 %s %s openidx - %s %s %s\n",
		priFor(e.Outcome), ts, sanitizeHost(hostname), msgID, sd, human)
}

// formatCEF renders an ArcSight CEF payload wrapped in an RFC 5424 syslog frame.
// CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
func formatCEF(hostname string, e siemEvent) string {
	sev := 3
	switch strings.ToLower(e.Outcome) {
	case "failure", "denied", "error":
		sev = 6
	}
	name := cefEscapeHeader(e.Action)
	if name == "" {
		name = "audit"
	}
	ext := cefExt("eventId", e.ID) +
		cefExt("cat", e.Category) +
		cefExt("outcome", e.Outcome) +
		cefExt("suser", e.ActorID) +
		cefExt("actorType", e.ActorType) +
		cefExt("src", e.ActorIP) +
		cefExt("duser", e.TargetID) +
		cefExt("targetType", e.Target) +
		cefExt("orgId", e.OrgID) +
		cefExt("rt", strconv.FormatInt(e.Timestamp.UTC().UnixMilli(), 10))
	cef := fmt.Sprintf("CEF:0|OpenIDX|OpenIDX|1|%s|%s|%d|%s",
		cefEscapeHeader(e.EventType), name, sev, strings.TrimSpace(ext))
	ts := e.Timestamp.UTC().Format(time.RFC3339)
	return fmt.Sprintf("<%d>1 %s %s openidx - - - %s\n",
		priFor(e.Outcome), ts, sanitizeHost(hostname), cef)
}

// ─── Splunk HEC sink ────────────────────────────────────────────────────────

type hecSink struct {
	cfg    SIEMConfig
	client *http.Client
}

func newHECSink(cfg SIEMConfig) *hecSink {
	return &hecSink{
		cfg: cfg,
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // operator opt-in for self-signed HEC
				},
			},
		},
	}
}

// hecEnvelope is one Splunk HEC event: {event:{...}, time, host, source, sourcetype}.
type hecEnvelope struct {
	Time       float64     `json:"time"`
	Host       string      `json:"host"`
	Source     string      `json:"source"`
	Sourcetype string      `json:"sourcetype"`
	Event      interface{} `json:"event"`
}

func (h *hecSink) deliver(events []siemEvent) error {
	// HEC accepts newline-delimited JSON envelopes in a single POST.
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, e := range events {
		env := hecEnvelope{
			Time:       float64(e.Timestamp.UTC().UnixMilli()) / 1000.0,
			Host:       h.cfg.Hostname,
			Source:     "openidx",
			Sourcetype: "openidx:audit",
			Event: map[string]interface{}{
				"event_id":    e.ID,
				"event_type":  e.EventType,
				"category":    e.Category,
				"action":      e.Action,
				"outcome":     e.Outcome,
				"org_id":      e.OrgID,
				"actor_id":    e.ActorID,
				"actor_type":  e.ActorType,
				"actor_ip":    e.ActorIP,
				"target_id":   e.TargetID,
				"target_type": e.Target,
				"details":     e.Details,
			},
		}
		if err := enc.Encode(&env); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPost, h.cfg.Endpoint, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+h.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HEC returned status %d", resp.StatusCode)
	}
	return nil
}

func (h *hecSink) Close() error { return nil }

// ─── formatting helpers ─────────────────────────────────────────────────────

// sdParam renders a single RFC 5424 SD-PARAM; empty values are omitted.
func sdParam(name, value string) string {
	if value == "" {
		return ""
	}
	// Escape ", \, ] per RFC 5424.
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return fmt.Sprintf(` %s="%s"`, name, r.Replace(value))
}

// sanitizeToken keeps MSGID/APP-NAME printable-ASCII and space-free.
func sanitizeToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r <= 32 || r > 126 {
			return '_'
		}
		return r
	}, s)
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

func sanitizeHost(s string) string {
	s = sanitizeToken(s)
	if s == "" {
		return "openidx"
	}
	return s
}

// cefEscapeHeader escapes CEF header fields (| and \).
func cefEscapeHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(strings.TrimSpace(s))
}

// cefExt renders a CEF extension key=value; empty values omitted; escapes = and \.
func cefExt(key, value string) string {
	if value == "" {
		return ""
	}
	v := strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", " ").Replace(value)
	return key + "=" + v + " "
}
