package access

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestGuacUsernameFor(t *testing.T) {
	cases := []struct{ email, username, id, want string }{
		{"a@x.com", "alice", "uid", "a@x.com"},
		{"", "alice", "uid", "alice"},
		{"  ", "", "uid", "uid"},
		{"", "", "", ""},
	}
	for _, c := range cases {
		if got := guacUsernameFor(c.email, c.username, c.id); got != c.want {
			t.Errorf("guacUsernameFor(%q,%q,%q)=%q want %q", c.email, c.username, c.id, got, c.want)
		}
	}
}

func TestRandomGuacPassword(t *testing.T) {
	a, err := randomGuacPassword()
	if err != nil || len(a) < 40 {
		t.Fatalf("pw=%q err=%v", a, err)
	}
	b, _ := randomGuacPassword()
	if a == b {
		t.Fatal("passwords should differ")
	}
}

func TestMintSessionTokenAs(t *testing.T) {
	var gotUser, gotXFF string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotUser = r.PostFormValue("username")
		gotXFF = r.Header.Get("X-Forwarded-For")
		_, _ = w.Write([]byte(`{"authToken":"USER-TOKEN","dataSource":"postgresql"}`))
	}))
	defer srv.Close()

	gc := &GuacamoleClient{baseURL: srv.URL, httpClient: srv.Client(), logger: zap.NewNop()}
	tok, err := gc.mintSessionTokenAs("bob@x.com", "pw", "1.2.3.4")
	if err != nil || tok != "USER-TOKEN" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	if gotUser != "bob@x.com" || gotXFF != "1.2.3.4" {
		t.Fatalf("user=%q xff=%q", gotUser, gotXFF)
	}

	// Blank client IP must omit the X-Forwarded-For header.
	gotXFF = "sentinel"
	if _, err := gc.mintSessionTokenAs("bob@x.com", "pw", ""); err != nil {
		t.Fatal(err)
	}
	if gotXFF != "" {
		t.Fatalf("expected no XFF header, got %q", gotXFF)
	}
}

func TestGrantRevokeConnectionRead(t *testing.T) {
	var lastPatch string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			b, _ := io.ReadAll(r.Body)
			lastPatch = string(b)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	gc := &GuacamoleClient{baseURL: srv.URL, dataSource: "postgresql", httpClient: srv.Client(), logger: zap.NewNop()}
	if err := gc.grantConnectionRead(context.Background(), "bob@x.com", "42"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastPatch, `"op":"add"`) || !strings.Contains(lastPatch, `/connectionPermissions/42`) || !strings.Contains(lastPatch, `"value":"READ"`) {
		t.Fatalf("grant body: %s", lastPatch)
	}
	if err := gc.revokeConnectionRead(context.Background(), "bob@x.com", "42"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastPatch, `"op":"remove"`) {
		t.Fatalf("revoke body: %s", lastPatch)
	}
}

func TestRevokeConnectionReadTolerates404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	gc := &GuacamoleClient{baseURL: srv.URL, dataSource: "postgresql", httpClient: srv.Client(), logger: zap.NewNop()}
	if err := gc.revokeConnectionRead(context.Background(), "bob@x.com", "42"); err != nil {
		t.Fatalf("revoke should tolerate 404, got %v", err)
	}
	// grant must NOT tolerate a non-2xx.
	if err := gc.grantConnectionRead(context.Background(), "bob@x.com", "42"); err == nil {
		t.Fatal("grant should error on 404")
	}
}

func TestMintShareKeyAsOwner(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.URL.Query().Get("token")
		_, _ = w.Write([]byte(`{"values":{"key":"SHARE-KEY-XYZ"}}`))
	}))
	defer srv.Close()
	gc := &GuacamoleClient{baseURL: srv.URL, dataSource: "postgresql", httpClient: srv.Client(), logger: zap.NewNop()}
	key, err := gc.mintShareKeyAsOwner(context.Background(), "OWNER-TOKEN", "active-uuid", "7")
	if err != nil || key != "SHARE-KEY-XYZ" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	if gotToken != "OWNER-TOKEN" {
		t.Fatalf("share key must be minted with the owner token, got %q", gotToken)
	}
}
