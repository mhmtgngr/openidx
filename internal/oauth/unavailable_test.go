package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/openidx/openidx/internal/common/cache"
)

func TestIsDependencyUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not unavailable", nil, false},
		{"redis unavailable", cache.ErrRedisUnavailable, true},
		{"wrapped redis unavailable", fmt.Errorf("get session: %w", cache.ErrRedisUnavailable), true},
		{"context deadline (dial timed out)", context.DeadlineExceeded, true},
		{"context canceled", context.Canceled, true},
		{"net dial error", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"pg admin shutdown 57P01", &pgconn.PgError{Code: "57P01"}, true},
		{"pg cannot connect now 57P03", &pgconn.PgError{Code: "57P03"}, true},
		{"pg connection exception 08006", &pgconn.PgError{Code: "08006"}, true},
		{"pg too many connections 53300", &pgconn.PgError{Code: "53300"}, true},
		{"pg read-only txn during failover 25006", &pgconn.PgError{Code: "25006"}, true},
		{"closed pool string", errors.New("closed pool"), true},
		{"connection refused string", errors.New("dial tcp: connection refused"), true},

		// Genuine application errors MUST NOT be misclassified as brownouts —
		// otherwise a bad password would tell the client to "retry shortly".
		{"unique violation 23505", &pgconn.PgError{Code: "23505"}, false},
		{"not-null violation 23502", &pgconn.PgError{Code: "23502"}, false},
		{"plain app error", errors.New("invalid credentials"), false},
		{"no rows", errors.New("no rows in result set"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDependencyUnavailable(tc.err); got != tc.want {
				t.Fatalf("isDependencyUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestWriteServerOrUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("transient outage -> 503 temporarily_unavailable with Retry-After", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		wrote503 := writeServerOrUnavailable(c, cache.ErrRedisUnavailable)
		if !wrote503 {
			t.Fatal("expected writeServerOrUnavailable to report a 503")
		}
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		if ra := w.Header().Get("Retry-After"); ra == "" {
			t.Fatal("expected a Retry-After header on the 503")
		}
		if body := w.Body.String(); !strings.Contains(body, ErrorTemporarilyUnavailable) {
			t.Fatalf("body %q should contain %q", body, ErrorTemporarilyUnavailable)
		}
	})

	t.Run("genuine server error -> 500 server_error, no Retry-After", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		wrote503 := writeServerOrUnavailable(c, errors.New("some logic bug"))
		if wrote503 {
			t.Fatal("expected a 500, not a 503, for a non-dependency error")
		}
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", w.Code)
		}
		if ra := w.Header().Get("Retry-After"); ra != "" {
			t.Fatalf("500 must not carry Retry-After, got %q", ra)
		}
		if body := w.Body.String(); !strings.Contains(body, ErrorServerError) {
			t.Fatalf("body %q should contain %q", body, ErrorServerError)
		}
	})
}
