package governance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// A "time-bound" elevation that was not bounded, by a parser that did not parse.
//
// handleCreateAccessRequest turns a duration string into access_requests
// .expires_at, which is the whole of what makes an elevation temporary. The
// parser behind it used fmt.Sscanf("%d"), which stops at the first byte it
// cannot read and reports success for what it got, while the unit came from the
// LAST byte of the string. Nothing checked the two met in the middle, and
// nothing bounded the result.
//
// The cases below are measured, not imagined: each one is what the old parser
// returned for that input.

func TestParseDurationRefusesWhatItUsedToAccept(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		was  string // what the old parser produced
		harm string
	}{
		{"0h", "0s", "an elevation that expires at the moment it is created"},
		{"-5d", "-120h", "expires_at five days in the PAST: a request created already expired"},
		{"9999999999999d", "-761598h", "int64 nanoseconds overflowed and wrapped negative — expires_at in 1939"},
		{"100000000d", "1923270h", "overflowed to the year 2246: the window stored is not the window chosen"},
		{"3zd", "72h", "the z was skipped and the trailing d read as the unit — 3 days, silently"},
		{"12 d", "288h", "the space was skipped — 12 days, silently"},
		{"d", "", "no value at all"},
		{"7", "", "no unit at all"},
		{"7w", "", "an unsupported unit"},
		{"1.5d", "", "not a whole number"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			d, err := parseDuration(tc.in)
			if err == nil {
				t.Errorf("parseDuration(%q) returned %v with no error. Old behaviour was %s — %s",
					tc.in, d, tc.was, tc.harm)
			}
		})
	}
}

// The windows the product documents must all still work: a ceiling that rejects
// what the handler's own comment offers as an example is a regression, not a
// control.
func TestParseDurationAcceptsEveryDocumentedWindow(t *testing.T) {
	t.Parallel()

	want := map[string]time.Duration{
		"4h": 4 * time.Hour, "8h": 8 * time.Hour,
		"1d": 24 * time.Hour, "3d": 72 * time.Hour, "7d": 168 * time.Hour,
		"30d": 720 * time.Hour, "90d": 2160 * time.Hour,
	}
	for in, expect := range want {
		got, err := parseDuration(in)
		if err != nil {
			t.Errorf("parseDuration(%q): %v — this is a window the product documents", in, err)
			continue
		}
		if got != expect {
			t.Errorf("parseDuration(%q) = %v, want %v", in, got, expect)
		}
	}
}

// The default ceiling must not reject anything the product previously offered.
// That is the whole justification for the number: 90d is the longest documented
// example, so defaulting there ends "unbounded" without breaking a single
// window the docs promise.
func TestTheDefaultCeilingAdmitsEveryDocumentedWindow(t *testing.T) {
	t.Parallel()

	s := &Service{logger: zap.NewNop()}
	max := s.maxAccessRequestDuration()
	for _, in := range []string{"4h", "8h", "1d", "3d", "7d", "30d", "90d"} {
		d, err := parseDuration(in)
		if err != nil {
			t.Fatalf("parseDuration(%q): %v", in, err)
		}
		if d > max {
			t.Errorf("the default ceiling (%v) rejects %q, which the product documents as supported",
				max, in)
		}
	}
}

// createRequest drives the handler far enough to reach the duration check. A
// role request touches no table before it, so this needs no database — and if
// the handler ever starts reading one first, a nil pool makes that loud rather
// than silent.
func createRequest(t *testing.T, s *Service, duration string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	body, err := json.Marshal(map[string]string{
		"resource_type": "role",
		"resource_id":   "ffffffff-0000-0000-0000-0000000000c1",
		"resource_name": "Payments admin",
		"justification": "on call this week",
		"duration":      duration,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/access-requests", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request = c.Request.WithContext(
		orgctx.With(context.Background(), orgctx.Org{ID: "00000000-0000-0000-0000-0000000000c1"}))
	c.Set("user_id", "11111111-0000-0000-0000-0000000000c1")
	s.handleCreateAccessRequest(c)
	return w
}

func TestAnAccessRequestOverTheCeilingIsRefusedAndSaysSo(t *testing.T) {
	t.Parallel()

	s := &Service{logger: zap.NewNop()}
	w := createRequest(t, s, "365d")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("a request for a year of standing access answered %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "90d") {
		t.Errorf("the refusal does not name the maximum, so the requester cannot ask for a window that "+
			"would be accepted: %s", w.Body.String())
	}
}

// Refused, never quietly shortened. An elevation granted for less than the
// window an approver read and approved is the same defect as one granted for
// longer, and neither party can see it.
func TestAnOverLongRequestIsNotSilentlyShortened(t *testing.T) {
	t.Parallel()

	s := &Service{logger: zap.NewNop()}
	w := createRequest(t, s, "365d")

	if w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Fatalf("the request was accepted (%d); if the window was clamped to the ceiling, the "+
			"approver will read one number and grant another: %s", w.Code, w.Body.String())
	}
}

func TestTheCeilingIsConfigurable(t *testing.T) {
	t.Parallel()

	// A deployment that allows nothing longer than a working day.
	s := &Service{logger: zap.NewNop(), config: &config.Config{AccessRequestMaxDurationHours: 8}}

	if got := s.maxAccessRequestDuration(); got != 8*time.Hour {
		t.Fatalf("maxAccessRequestDuration = %v, want 8h", got)
	}

	w := createRequest(t, s, "1d")
	if w.Code != http.StatusBadRequest {
		t.Errorf("a one-day request under an 8h ceiling answered %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "8h") {
		t.Errorf("the refusal does not name this deployment's maximum: %s", w.Body.String())
	}
}

// An unset or nonsensical configured value falls back to the default rather
// than to zero — a ceiling of zero would refuse every request, which is a
// louder failure than no ceiling but still the wrong one.
func TestAnUnsetCeilingFallsBackToTheDefault(t *testing.T) {
	t.Parallel()

	for _, cfg := range []*config.Config{
		nil,
		{},
		{AccessRequestMaxDurationHours: 0},
		{AccessRequestMaxDurationHours: -1},
	} {
		s := &Service{logger: zap.NewNop(), config: cfg}
		if got := s.maxAccessRequestDuration(); got != defaultAccessRequestMaxHours*time.Hour {
			t.Errorf("with config %+v the ceiling is %v, want the %dh default", cfg, got, defaultAccessRequestMaxHours)
		}
	}
}
