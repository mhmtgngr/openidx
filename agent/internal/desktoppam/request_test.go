package desktoppam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestAccessFilesTheReasonAndReportsARefusal(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/entries/e1/request") || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["reason"] == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"reason is required"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"request_id":"r1"}`))
	}))
	t.Cleanup(srv.Close)

	if err := RequestAccess(context.Background(), srv.URL, "tok", "e1", "from the tray on host-1"); err != nil {
		t.Fatalf("RequestAccess: %v", err)
	}
	if got["reason"] != "from the tray on host-1" {
		t.Fatalf("reason sent %q", got["reason"])
	}

	err := RequestAccess(context.Background(), srv.URL, "tok", "e1", "")
	var ref *Refusal
	if !errors.As(err, &ref) || ref.Status != 400 || !strings.Contains(ref.Code, "reason") {
		t.Fatalf("a refused request keeps the server's reason: %v", err)
	}
	if err := RequestAccess(context.Background(), srv.URL, "wrong", "e1", "x"); !errors.As(err, &ref) || ref.Status != 401 {
		t.Fatalf("a refused token: %v", err)
	}
}
