package directory

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// bambooMockDirectory is a canned /v1/employees/directory payload covering a
// joiner (active), a mover-ish record with dept/title/manager, and a leaver
// (terminated with a past termination date).
const bambooMockDirectory = `{
  "employees": [
    {"id":"101","employeeNumber":"E101","displayName":"Ada Lovelace","firstName":"Ada","lastName":"Lovelace",
     "workEmail":"ada@corp.com","jobTitle":"Engineer","department":"R&D","supervisorEId":"201",
     "status":"Active","hireDate":"2024-01-15","terminationDate":"0000-00-00"},
    {"id":"102","employeeNumber":"E102","displayName":"Alan Turing","firstName":"Alan","lastName":"Turing",
     "workEmail":"alan@corp.com","jobTitle":"Principal","department":"R&D","supervisorEId":"",
     "status":"Active","hireDate":"2023-06-01"},
    {"id":"103","employeeNumber":"E103","displayName":"Grace Hopper","firstName":"Grace","lastName":"Hopper",
     "workEmail":"grace@corp.com","jobTitle":"Admiral","department":"Navy","supervisorEId":"201",
     "status":"Terminated","hireDate":"2020-01-01","terminationDate":"2025-01-01"},
    {"id":"104","displayName":"No Email","firstName":"No","lastName":"Email","employeeNumber":"E104",
     "workEmail":"","status":"Active"}
  ]
}`

func newBambooMock(t *testing.T, wantKey string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Basic auth: base64(apiKey:x).
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantKey+":x"))
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/v1/employees/directory") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(bambooMockDirectory))
	}))
}

func newBambooConnector(srv *httptest.Server, key string) *BambooHRConnector {
	c := NewBambooHRConnector(HRISConfig{Provider: "bamboohr", APIKey: key, BaseURL: srv.URL}, zap.NewNop())
	c.client = srv.Client()
	return c
}

func TestBambooTestConnection(t *testing.T) {
	srv := newBambooMock(t, "secret-key")
	defer srv.Close()
	c := newBambooConnector(srv, "secret-key")
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}

func TestBambooTestConnectionBadKey(t *testing.T) {
	srv := newBambooMock(t, "secret-key")
	defer srv.Close()
	c := newBambooConnector(srv, "wrong-key")
	if err := c.TestConnection(context.Background()); err == nil {
		t.Fatal("expected auth failure with wrong key")
	}
}

func TestBambooTestConnectionRequiresKey(t *testing.T) {
	c := NewBambooHRConnector(HRISConfig{Subdomain: "acme"}, zap.NewNop())
	if err := c.TestConnection(context.Background()); err == nil {
		t.Fatal("expected error when api_key missing")
	}
}

func TestBambooSearchUsersMapping(t *testing.T) {
	srv := newBambooMock(t, "k")
	defer srv.Close()
	c := newBambooConnector(srv, "k")

	recs, err := c.SearchUsers(context.Background())
	if err != nil {
		t.Fatalf("SearchUsers: %v", err)
	}
	// 4 employees, all have email or employee number -> all mapped.
	if len(recs) != 4 {
		t.Fatalf("expected 4 records, got %d", len(recs))
	}

	byEmail := map[string]UserRecord{}
	byNum := map[string]UserRecord{}
	for _, r := range recs {
		if r.Email != "" {
			byEmail[r.Email] = r
		}
		byNum[r.EmployeeNumber] = r
	}

	ada := byEmail["ada@corp.com"]
	if ada.Username != "ada@corp.com" {
		t.Errorf("expected email username, got %q", ada.Username)
	}
	if ada.JobTitle != "Engineer" || ada.Department != "R&D" || ada.ManagerExternal != "201" {
		t.Errorf("ada HR attrs wrong: %+v", ada)
	}
	if ada.EmploymentStatus != "active" {
		t.Errorf("expected ada active, got %q", ada.EmploymentStatus)
	}
	if ada.HireDate != "2024-01-15" {
		t.Errorf("expected ada hire date, got %q", ada.HireDate)
	}
	// "0000-00-00" termination normalized to empty.
	if ada.TerminationDate != "" {
		t.Errorf("expected empty termination for ada, got %q", ada.TerminationDate)
	}

	grace := byEmail["grace@corp.com"]
	if grace.EmploymentStatus != "terminated" {
		t.Errorf("expected grace terminated, got %q", grace.EmploymentStatus)
	}
	if grace.TerminationDate != "2025-01-01" {
		t.Errorf("expected grace termination date, got %q", grace.TerminationDate)
	}

	// Employee without email falls back to employee-number username.
	noEmail := byNum["E104"]
	if noEmail.Username != "E104" {
		t.Errorf("expected employee-number username fallback, got %q", noEmail.Username)
	}
}

func TestBambooUsernameFieldEmployeeNumber(t *testing.T) {
	srv := newBambooMock(t, "k")
	defer srv.Close()
	c := NewBambooHRConnector(HRISConfig{APIKey: "k", BaseURL: srv.URL, UsernameField: "employee_number"}, zap.NewNop())
	c.client = srv.Client()

	recs, _ := c.SearchUsers(context.Background())
	for _, r := range recs {
		if r.EmployeeNumber != "" && r.Username != r.EmployeeNumber {
			t.Errorf("expected employee-number username, got %q for %s", r.Username, r.EmployeeNumber)
		}
	}
}

func TestDeriveStatus(t *testing.T) {
	cases := []struct {
		raw, term, want string
	}{
		{"Active", "", "active"},
		{"Terminated", "2025-01-01", "terminated"},
		{"On Leave", "", "on_leave"},
		{"", "2020-01-01", "terminated"}, // past term date, no status
		{"", "", "active"},               // present in directory, no signal
		{"", "2999-01-01", "active"},     // future term date -> still active
	}
	for _, tc := range cases {
		if got := deriveStatus(tc.raw, tc.term); got != tc.want {
			t.Errorf("deriveStatus(%q,%q)=%q want %q", tc.raw, tc.term, got, tc.want)
		}
	}
}

func TestNormalizeDate(t *testing.T) {
	cases := map[string]string{
		"2024-01-15":          "2024-01-15",
		"0000-00-00":          "",
		"":                    "",
		"2024-01-15T00:00:00": "2024-01-15",
	}
	for in, want := range cases {
		if got := normalizeDate(in); got != want {
			t.Errorf("normalizeDate(%q)=%q want %q", in, got, want)
		}
	}
}
