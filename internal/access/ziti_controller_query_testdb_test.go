package access

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// WHAT A REQUEST CAN PUT INTO THE CONTROLLER'S QUERIES.
//
// The session list filters by type in the controller's own query language. It
// takes the controller's two session types, in any case, and sends the filter
// query-escaped; any other value is refused with 400 before the controller is
// asked, so a value cannot rewrite the filter or add parameters to the
// request. An id taken from the request path reaches the controller as one
// path segment, never as a query string.
func TestTheControllersQueriesTakeOnlyWhatTheyAskFor(t *testing.T) {
	f := newZitiScopeFixture(t)
	var mu sync.Mutex
	var queries []url.Values
	f.stub.on("GET /edge/management/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	last := func() url.Values {
		mu.Lock()
		defer mu.Unlock()
		if len(queries) == 0 {
			return nil
		}
		return queries[len(queries)-1]
	}

	operator := f.caller("operatorB", "operator")
	for raw, want := range map[string]string{"Dial": `type="Dial"`, "bind": `type="Bind"`} {
		code, body := f.do(operator, http.MethodGet, "/api/v1/access/ziti/sessions?type="+url.QueryEscape(raw), "")
		if code != http.StatusOK {
			t.Errorf("sessions of type %s: %d %s, want 200", raw, code, body)
			continue
		}
		q := last()
		if got := q.Get("filter"); got != want || len(q["filter"]) != 1 || q.Get("limit") != "200" {
			t.Errorf("sessions of type %s asked the controller for %v, want the one filter %s and limit 200", raw, q, want)
		}
	}

	for _, raw := range []string{
		`Dial" or type != "Dial`,
		`Dial"&limit=100000&filter=true`,
		`Dial" limit 100000`,
		"Terminate",
	} {
		mu.Lock()
		asked := len(queries)
		mu.Unlock()
		code, body := f.do(operator, http.MethodGet, "/api/v1/access/ziti/sessions?type="+url.QueryEscape(raw), "")
		if code != http.StatusBadRequest || !strings.Contains(body, "type must be Dial or Bind") {
			t.Errorf("sessions of type %q: %d %s, want 400 type must be Dial or Bind", raw, code, body)
		}
		mu.Lock()
		if len(queries) != asked {
			t.Errorf("sessions of type %q reached the controller with %v", raw, queries[len(queries)-1])
		}
		mu.Unlock()
	}

	// An id with a query string in it reaches the controller as one path
	// segment on every route that puts an id from its own path into the
	// controller's, never as a query string -- also where an organization's
	// admin names it and the controller is asked for it before its owner is
	// known.
	type call struct{ method, path, query string }
	var calls []call
	// The recorder answers every write, and every read of one object by id;
	// the fixture's own handlers keep answering the lists.
	for _, pattern := range []string{
		"PUT /edge/management/v1/", "PATCH /edge/management/v1/", "DELETE /edge/management/v1/",
		"GET /edge/management/v1/terminators/", "GET /edge/management/v1/edge-routers/",
		"GET /edge/management/v1/services/", "GET /edge/management/v1/identities/",
		"GET /edge/management/v1/sessions/",
	} {
		f.stub.on(pattern, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			calls = append(calls, call{r.Method, r.URL.Path, r.URL.RawQuery})
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"x","roleAttributes":[]}}`))
		})
	}
	const id, decoded = "x-id%3Fx=1", "x-id?x=1"
	admin, adminB := f.caller("adminA", "admin"), f.caller("adminB", "admin")
	for _, rq := range []struct {
		cl                          zitiCaller
		method, path, body, reaches string
	}{
		{admin, http.MethodPut, "/api/v1/access/ziti/configs/" + id, `{"name":"n","data":{}}`, "PUT /edge/management/v1/configs/"},
		{admin, http.MethodDelete, "/api/v1/access/ziti/configs/" + id, "", "DELETE /edge/management/v1/configs/"},
		{admin, http.MethodPut, "/api/v1/access/ziti/edge-router-policies/" + id, `{"name":"n"}`, "PUT /edge/management/v1/edge-router-policies/"},
		{admin, http.MethodDelete, "/api/v1/access/ziti/edge-router-policies/" + id, "", "DELETE /edge/management/v1/edge-router-policies/"},
		{admin, http.MethodPut, "/api/v1/access/ziti/auth-policies/" + id, `{"name":"n"}`, "PUT /edge/management/v1/auth-policies/"},
		{admin, http.MethodDelete, "/api/v1/access/ziti/auth-policies/" + id, "", "DELETE /edge/management/v1/auth-policies/"},
		{admin, http.MethodPut, "/api/v1/access/ziti/jwt-signers/" + id, `{"name":"n"}`, "PUT /edge/management/v1/external-jwt-signers/"},
		{admin, http.MethodDelete, "/api/v1/access/ziti/jwt-signers/" + id, "", "DELETE /edge/management/v1/external-jwt-signers/"},
		{admin, http.MethodGet, "/api/v1/access/ziti/terminators/" + id, "", "GET /edge/management/v1/terminators/"},
		{admin, http.MethodDelete, "/api/v1/access/ziti/terminators/" + id, "", "DELETE /edge/management/v1/terminators/"},
		{admin, http.MethodDelete, "/api/v1/access/ziti/sessions/" + id, "", "DELETE /edge/management/v1/sessions/"},
		{admin, http.MethodGet, "/api/v1/access/ziti/fabric/routers/" + id, "", "GET /edge/management/v1/edge-routers/"},
		{admin, http.MethodPost, "/api/v1/access/ziti/browzer/services/" + id + "/enable", "", "GET /edge/management/v1/services/"},
		{admin, http.MethodPost, "/api/v1/access/ziti/browzer/services/" + id + "/enable", "", "PATCH /edge/management/v1/services/"},
		{admin, http.MethodPost, "/api/v1/access/ziti/ai/identities/" + id + "/quarantine", "", "GET /edge/management/v1/identities/"},
		{admin, http.MethodPost, "/api/v1/access/ziti/ai/identities/" + id + "/unquarantine", "", "PATCH /edge/management/v1/identities/"},
		{adminB, http.MethodDelete, "/api/v1/access/ziti/sessions/" + id, "", "GET /edge/management/v1/sessions/"},
		{adminB, http.MethodDelete, "/api/v1/access/ziti/terminators/" + id, "", "GET /edge/management/v1/terminators/"},
	} {
		mu.Lock()
		calls = nil
		mu.Unlock()
		f.do(rq.cl, rq.method, rq.path, rq.body)
		method, prefix, _ := strings.Cut(rq.reaches, " ")
		mu.Lock()
		found := false
		for _, c := range calls {
			if c.method != method || !strings.HasPrefix(c.path, prefix) {
				continue
			}
			found = true
			if c.path != prefix+decoded || c.query != "" {
				t.Errorf("%s %s as %s asked the controller for %s %q with query %q, want the id as one segment and no query",
					rq.method, rq.path, rq.cl.name, c.method, c.path, c.query)
			}
		}
		mu.Unlock()
		if !found {
			t.Errorf("%s %s as %s did not reach %s: %v", rq.method, rq.path, rq.cl.name, rq.reaches, calls)
		}
	}
}

// Explaining a service asks the controller for its terminators by the id the
// controller gave the service, never by the name in the request, which is text
// an administrator chose.
func TestExplainAsksForTerminatorsByTheServicesID(t *testing.T) {
	f := newZitiScopeFixture(t)
	var mu sync.Mutex
	var filters []string
	f.stub.on("GET /edge/management/v1/terminators", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		filters = append(filters, r.URL.Query().Get("filter"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	if code, body := f.do(f.caller("adminB", "admin"), http.MethodGet,
		"/api/v1/access/ziti/services/by-name/"+f.svcB+"/explain", ""); code != http.StatusOK {
		t.Fatalf("explain B's service as B's admin: %d %s", code, body)
	}
	mu.Lock()
	defer mu.Unlock()
	want := `service="` + f.zsB + `"`
	for _, got := range filters {
		if got == want {
			return
		}
	}
	t.Errorf("the controller was asked for terminators with filters %q, want %s", filters, want)
}

// A name looked up on the controller -- a service, config, policy or identity
// name an administrator chose -- reaches it, on every lookup that filters by
// one, as one filter holding the name as one quoted string: a quote cannot end
// the string and an ampersand cannot start another parameter. The service
// lookups still find the service by its exact name.
func TestANameReachesTheControllersFilterAsOneQuotedValue(t *testing.T) {
	stub := newZitiStub(t)
	name := `svc" or name != "x&limit=1`
	var mu sync.Mutex
	var asked []*url.URL
	stub.on("GET /edge/management/v1/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"svc-1","name":` + strconv.Quote(name) + `}]}`))
	})
	zm := zitiManagerAgainst(t, stub, nil)
	ctx := context.Background()
	for _, lk := range []struct {
		what, path, field string
		lookup            func() string // the id a service lookup found; "" for the others
	}{
		{"serviceIDByName", "/edge/management/v1/services", "name", func() string {
			id, _ := zm.serviceIDByName(ctx, name)
			return id
		}},
		{"pamZitiServiceID", "/edge/management/v1/services", "name", func() string {
			id, _ := (&Service{}).pamZitiServiceID(ctx, zm, name)
			return id
		}},
		{"deleteEdgeEntityByName", "/edge/management/v1/configs", "name", func() string {
			_ = zm.deleteEdgeEntityByName(ctx, "configs", name)
			return ""
		}},
		{"CreateHostV1ConfigFixed", "/edge/management/v1/configs", "name", func() string {
			_, _ = zm.CreateHostV1ConfigFixed(ctx, name, "192.0.2.1", 80)
			return ""
		}},
		{"CreateInterceptV1ConfigFixed", "/edge/management/v1/configs", "name", func() string {
			_, _ = zm.CreateInterceptV1ConfigFixed(ctx, name, "192.0.2.1", 80)
			return ""
		}},
		{"findIdentityByExternalID", "/edge/management/v1/identities", "externalId", func() string {
			_ = zm.findIdentityByExternalID(name)
			return ""
		}},
		{"findResourceByName", "/edge/management/v1/auth-policies", "name", func() string {
			_ = zm.findResourceByName("auth-policies", name)
			return ""
		}},
	} {
		mu.Lock()
		asked = nil
		mu.Unlock()
		id := lk.lookup()
		if strings.HasSuffix(lk.path, "/services") && id != "svc-1" {
			t.Errorf("%s found %q, want svc-1", lk.what, id)
		}
		mu.Lock()
		var filters []url.Values
		for _, u := range asked {
			if u.Path == lk.path && u.Query().Has("filter") {
				filters = append(filters, u.Query())
			}
		}
		mu.Unlock()
		want := lk.field + "=" + strconv.Quote(name)
		if len(filters) == 0 {
			t.Errorf("%s did not look the name up on %s", lk.what, lk.path)
		}
		for _, q := range filters {
			if len(q) != 1 || len(q["filter"]) != 1 || q.Get("filter") != want {
				t.Errorf("%s asked the controller %v, want one filter %s", lk.what, q, want)
			}
		}
	}
}
