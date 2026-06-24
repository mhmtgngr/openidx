package access

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPISIXClientPutListDelete(t *testing.T) {
	var gotKey, gotMethod, gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotMethod, gotPath = r.Header.Get("X-API-KEY"), r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"list":[{"value":{"id":"browzer-a"}},{"value":{"id":"other"}}]}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := NewAPISIXClient(srv.URL, "secret")
	if err := c.PutRoute(context.Background(), "browzer-a", []byte(`{"uri":"/*"}`)); err != nil {
		t.Fatalf("PutRoute: %v", err)
	}
	if gotKey != "secret" || gotMethod != "PUT" || !strings.HasSuffix(gotPath, "/apisix/admin/routes/browzer-a") || gotBody != `{"uri":"/*"}` {
		t.Fatalf("PUT wrong: key=%s method=%s path=%s body=%s", gotKey, gotMethod, gotPath, gotBody)
	}
	names, err := c.ListRouteNames(context.Background())
	if err != nil {
		t.Fatalf("ListRouteNames: %v", err)
	}
	if len(names) != 2 || names[0] != "browzer-a" {
		t.Fatalf("ListRouteNames got %v", names)
	}
	if err := c.DeleteRoute(context.Background(), "browzer-a"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Fatalf("expected DELETE, got %s", gotMethod)
	}
}
