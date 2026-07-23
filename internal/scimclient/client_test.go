package scimclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockSP is an in-memory SCIM 2.0 service provider used to exercise the client
// end-to-end without a real SaaS. It implements just enough of RFC 7644 to
// validate create/replace/patch-active/delete for Users and Groups.
type mockSP struct {
	t         *testing.T
	users     map[string]*User
	groups    map[string]*Group
	nextID    int
	wantAuth  string
	patchOK   bool
	lastPatch *PatchRequest
}

func newMockSP(t *testing.T) *mockSP {
	return &mockSP{t: t, users: map[string]*User{}, groups: map[string]*Group{}, patchOK: true, wantAuth: "Bearer secret-token"}
}

func (m *mockSP) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/ServiceProviderConfig", func(w http.ResponseWriter, r *http.Request) {
		if !m.checkAuth(w, r) {
			return
		}
		spc := ServiceProviderConfig{}
		spc.Patch.Supported = m.patchOK
		spc.Filter.Supported = true
		writeJSON(w, http.StatusOK, spc)
	})

	mux.HandleFunc("/Users", func(w http.ResponseWriter, r *http.Request) {
		if !m.checkAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var u User
		json.NewDecoder(r.Body).Decode(&u)
		if u.UserName == "" {
			m.scimErr(w, http.StatusBadRequest, "invalidValue", "userName required")
			return
		}
		// Conflict on duplicate userName.
		for _, ex := range m.users {
			if ex.UserName == u.UserName {
				m.scimErr(w, http.StatusConflict, "uniqueness", "userName exists")
				return
			}
		}
		m.nextID++
		u.ID = "u" + itoa(m.nextID)
		m.users[u.ID] = &u
		writeJSON(w, http.StatusCreated, u)
	})

	mux.HandleFunc("/Users/", func(w http.ResponseWriter, r *http.Request) {
		if !m.checkAuth(w, r) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/Users/")
		switch r.Method {
		case http.MethodPut:
			if _, ok := m.users[id]; !ok {
				m.scimErr(w, http.StatusNotFound, "", "not found")
				return
			}
			var u User
			json.NewDecoder(r.Body).Decode(&u)
			u.ID = id
			m.users[id] = &u
			writeJSON(w, http.StatusOK, u)
		case http.MethodPatch:
			u, ok := m.users[id]
			if !ok {
				m.scimErr(w, http.StatusNotFound, "", "not found")
				return
			}
			var pr PatchRequest
			json.NewDecoder(r.Body).Decode(&pr)
			m.lastPatch = &pr
			for _, op := range pr.Operations {
				if strings.EqualFold(op.Path, "active") {
					if b, ok := op.Value.(bool); ok {
						u.Active = b
					}
				}
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if _, ok := m.users[id]; !ok {
				m.scimErr(w, http.StatusNotFound, "", "not found")
				return
			}
			delete(m.users, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/Groups", func(w http.ResponseWriter, r *http.Request) {
		if !m.checkAuth(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var g Group
		json.NewDecoder(r.Body).Decode(&g)
		m.nextID++
		g.ID = "g" + itoa(m.nextID)
		m.groups[g.ID] = &g
		writeJSON(w, http.StatusCreated, g)
	})

	mux.HandleFunc("/Groups/", func(w http.ResponseWriter, r *http.Request) {
		if !m.checkAuth(w, r) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/Groups/")
		switch r.Method {
		case http.MethodDelete:
			if _, ok := m.groups[id]; !ok {
				m.scimErr(w, http.StatusNotFound, "", "not found")
				return
			}
			delete(m.groups, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	return mux
}

func (m *mockSP) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != m.wantAuth {
		m.scimErr(w, http.StatusUnauthorized, "", "bad token")
		return false
	}
	return true
}

func (m *mockSP) scimErr(w http.ResponseWriter, status int, scimType, detail string) {
	writeJSON(w, status, map[string]interface{}{
		"schemas":  []string{SchemaError},
		"status":   itoa(status),
		"scimType": scimType,
		"detail":   detail,
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func newTestClient(t *testing.T, srv *httptest.Server, token string) *Client {
	c, err := New(Config{BaseURL: srv.URL, Bearer: token, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewRequiresBaseURL(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty BaseURL")
	}
	if _, err := New(Config{BaseURL: "https://x/scim/v2/"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProbe(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	spc, err := c.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !spc.Patch.Supported {
		t.Error("expected patch supported")
	}
}

func TestProbeBadAuth(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "wrong")

	_, err := c.Probe(context.Background())
	if err == nil {
		t.Fatal("expected auth error")
	}
	ae, ok := err.(*APIError)
	if !ok || ae.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 APIError, got %v", err)
	}
}

func TestCreateUser(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	u := &User{UserName: "alice@corp.com", DisplayName: "Alice", Active: true,
		Emails: []Email{{Value: "alice@corp.com", Primary: true}}}
	out, err := c.CreateUser(context.Background(), u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if out.ID == "" {
		t.Fatal("expected remote id")
	}
	if !containsSchema(out.Schemas, SchemaUser) {
		t.Errorf("expected user schema, got %v", out.Schemas)
	}
	if len(sp.users) != 1 {
		t.Errorf("expected 1 user on SP, got %d", len(sp.users))
	}
}

func TestCreateUserConflict(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	u := &User{UserName: "dup@corp.com", Active: true}
	if _, err := c.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := c.CreateUser(context.Background(), &User{UserName: "dup@corp.com", Active: true})
	if !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestEnterpriseUserSchemaAdded(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	u := &User{UserName: "bob@corp.com", Active: true,
		Enterprise: &EnterpriseUser{Department: "Eng", EmployeeNumber: "E42"}}
	out, err := c.CreateUser(context.Background(), u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !containsSchema(out.Schemas, SchemaEnterpriseUser) {
		t.Errorf("enterprise schema not added: %v", out.Schemas)
	}
}

func TestSetUserActiveDeactivate(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	out, _ := c.CreateUser(context.Background(), &User{UserName: "carol@corp.com", Active: true})
	if err := c.SetUserActive(context.Background(), out.ID, false); err != nil {
		t.Fatalf("SetUserActive: %v", err)
	}
	if sp.users[out.ID].Active {
		t.Error("expected user deactivated on SP")
	}
	if sp.lastPatch == nil || sp.lastPatch.Operations[0].Path != "active" {
		t.Errorf("expected active patch, got %+v", sp.lastPatch)
	}
}

func TestReplaceUser(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	out, _ := c.CreateUser(context.Background(), &User{UserName: "dave@corp.com", DisplayName: "Dave", Active: true})
	out.DisplayName = "David"
	rep, err := c.ReplaceUser(context.Background(), out.ID, out)
	if err != nil {
		t.Fatalf("ReplaceUser: %v", err)
	}
	if rep.DisplayName != "David" {
		t.Errorf("expected updated displayName, got %q", rep.DisplayName)
	}
}

func TestDeleteUserIdempotent(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	out, _ := c.CreateUser(context.Background(), &User{UserName: "erin@corp.com", Active: true})
	if err := c.DeleteUser(context.Background(), out.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	// Second delete: SP returns 404, client treats as success.
	if err := c.DeleteUser(context.Background(), out.ID); err != nil {
		t.Fatalf("idempotent DeleteUser: %v", err)
	}
}

func TestCreateAndDeleteGroup(t *testing.T) {
	sp := newMockSP(t)
	srv := httptest.NewServer(sp.handler())
	defer srv.Close()
	c := newTestClient(t, srv, "secret-token")

	g, err := c.CreateGroup(context.Background(), &Group{DisplayName: "Engineers"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if g.ID == "" {
		t.Fatal("expected group remote id")
	}
	if err := c.DeleteGroup(context.Background(), g.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if err := c.DeleteGroup(context.Background(), g.ID); err != nil {
		t.Fatalf("idempotent DeleteGroup: %v", err)
	}
}

func TestContentTypeHeader(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		_ = body
		writeJSON(w, http.StatusCreated, User{ID: "u1", UserName: "z@z"})
	}))
	defer srv.Close()
	c := newTestClient(t, srv, "")
	if _, err := c.CreateUser(context.Background(), &User{UserName: "z@z", Active: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if gotCT != "application/scim+json" {
		t.Errorf("expected scim+json content type, got %q", gotCT)
	}
}
