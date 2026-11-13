package access

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Controller v1.6.12 answers 404 to POST /identities/{id}/re-enroll. A device
// whose identity was enrolled under an old controller address then could never
// be handed a fresh token. The fallback creates one with POST /enrollments and
// reads it from the identity's enrollments list.
func TestReEnrollFallsBackToCreatingAnEnrollment(t *testing.T) {
	var created map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/edge/management/v1/identities/id1/enrollments":
			if created == nil {
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"id":"e1","method":"ott","jwt":"fresh.jwt.token"}]}`))
		case r.Method == "POST" && r.URL.Path == "/edge/management/v1/identities/id1/re-enroll":
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "POST" && r.URL.Path == "/edge/management/v1/enrollments":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &created)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"e1"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	zm := newTestZitiManager(t, srv.URL)
	jwt, err := zm.ReEnrollIdentity(context.Background(), "id1")
	if err != nil {
		t.Fatal(err)
	}
	if jwt != "fresh.jwt.token" {
		t.Fatalf("jwt = %q", jwt)
	}
	if created["identityId"] != "id1" || created["method"] != "ott" || created["expiresAt"] == nil {
		t.Fatalf("enrollment created with %v", created)
	}
}
