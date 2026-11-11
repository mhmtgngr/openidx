package transport

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClaimSendsBothCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/access/agent/claim" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer user-at" || r.Header.Get("X-Agent-ID") != "a1" ||
			r.Header.Get("X-Auth-Token") != "dev-tok" {
			t.Errorf("credentials: %v", r.Header)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "a1", "owner_user_id": "u1", "claimed": true})
	}))
	defer srv.Close()
	got, err := NewClient(srv.URL, "dev-tok", "a1").Claim("user-at")
	if err != nil || !got.Claimed || got.OwnerUserID != "u1" {
		t.Fatalf("Claim = %+v, %v", got, err)
	}
}

func TestClaimOwnedByAnotherIsDistinct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, "t", "a").Claim("x"); !errors.Is(err, ErrClaimOwnedByAnother) {
		t.Fatalf("err = %v, want ErrClaimOwnedByAnother", err)
	}
}
