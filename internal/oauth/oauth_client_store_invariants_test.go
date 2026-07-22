package oauth

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestOAuthClientStoreWritesUsePrimary guards the Repository invariant in the
// oauth service (mirrors the identity guard): Create/Update/Delete must use the
// PRIMARY pool (db.Pool), never db.Reader().
func TestOAuthClientStoreWritesUsePrimary(t *testing.T) {
	src, err := os.ReadFile("oauth_client_store.go")
	if err != nil {
		t.Fatalf("read oauth_client_store.go: %v", err)
	}
	for _, method := range []string{"Create", "Update", "Delete"} {
		body := storeMethodBody(string(src), method)
		if body == "" {
			t.Fatalf("could not find method %s", method)
		}
		if strings.Contains(body, ".Reader(") {
			t.Errorf("write method %s uses .Reader() (must use the primary db.Pool)", method)
		}
	}
}

// TestOAuthClientGetUsesPrimary pins the deliberate choice: client lookup gates
// every token grant and validates the secret, so it reads the PRIMARY (a
// just-rotated secret / disabled client must be seen immediately). List, by
// contrast, is allowed on the replica.
func TestOAuthClientGetUsesPrimary(t *testing.T) {
	src, err := os.ReadFile("oauth_client_store.go")
	if err != nil {
		t.Fatalf("read oauth_client_store.go: %v", err)
	}
	get := storeMethodBody(string(src), "GetByClientID")
	if get == "" {
		t.Fatal("could not find GetByClientID")
	}
	if strings.Contains(get, ".Reader(") {
		t.Error("GetByClientID must read the PRIMARY (security-critical client validation)")
	}
	// List should use the replica (offload the admin/dashboard path).
	list := storeMethodBody(string(src), "List")
	if list != "" && !strings.Contains(list, ".Reader(") {
		t.Error("List should read the replica via db.Reader()")
	}
}

func storeMethodBody(src, method string) string {
	re := regexp.MustCompile(`func \(r \*PostgresOAuthClientStore\) ` + regexp.QuoteMeta(method) + `\(`)
	loc := re.FindStringIndex(src)
	if loc == nil {
		return ""
	}
	rest := src[loc[0]:]
	depth := 0
	started := false
	for i, r := range rest {
		switch r {
		case '{':
			depth++
			started = true
		case '}':
			depth--
			if started && depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}
