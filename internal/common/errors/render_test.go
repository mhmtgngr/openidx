package errors

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func init() { gin.SetMode(gin.TestMode) }

// TestHandleErrorDoesNotLeakInternalError is the security guarantee: a wrapped
// internal error (which may contain SQL/hostnames) is NEVER written to the client
// body — only the safe generic message.
func TestHandleErrorDoesNotLeakInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	secret := "pq: password authentication failed for user openidx_app at host 10.0.3.7"
	HandleError(c, errors.New(secret))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("internal error leaked to client body: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "10.0.3.7") || strings.Contains(w.Body.String(), "openidx_app") {
		t.Fatalf("internal detail leaked: %s", w.Body.String())
	}
	// The client should still get a usable, typed code.
	if !strings.Contains(w.Body.String(), string(ErrInternal)) {
		t.Fatalf("expected a typed error code in body, got %s", w.Body.String())
	}
}

// TestHandleErrorWithLoggerLogsButHidesInternal proves the observability fix: the
// real cause is logged server-side (with the error) while staying out of the
// response body.
func TestHandleErrorWithLoggerLogsButHidesInternal(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("request_id", "req-abc")

	secret := "dial tcp 10.0.3.7:5432: connect: connection refused"
	HandleErrorWithLogger(c, DatabaseError("get user", errors.New(secret)), logger)

	// Client body must not contain the secret.
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("internal error leaked to client: %s", w.Body.String())
	}

	// Server logs MUST contain it (so we can debug).
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected exactly 1 error log, got %d", len(entries))
	}
	found := false
	for _, f := range entries[0].Context {
		// zap.Error stores the error in the field's Interface, keyed "error".
		if f.Key == "error" {
			if e, ok := f.Interface.(error); ok && strings.Contains(e.Error(), secret) {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected the internal error to be logged server-side; log = %v", entries[0])
	}
}

// TestHandleErrorWithLoggerSkipsLogFor4xx proves client errors (4xx) don't spam
// error-level logs.
func TestHandleErrorWithLoggerSkipsLogFor4xx(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	logger := zap.New(core)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	HandleErrorWithLogger(c, NotFound("user"), logger)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if logs.Len() != 0 {
		t.Fatalf("4xx should not produce error logs, got %d", logs.Len())
	}
}
