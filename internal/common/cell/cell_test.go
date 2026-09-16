package cell

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestMisdirectedOnlyWhenBothCellsAreKnownAndDiffer(t *testing.T) {
	cases := []struct {
		name           string
		token, serving string
		want           bool
	}{
		{"same cell", "eu-1", "eu-1", false},
		{"different cells", "eu-1", "us-1", true},
		// Every install today. With no CELL_ID there is no cell to be wrong
		// about, and nothing may change for a single-cell deployment.
		{"this install is not celled", "eu-1", "", false},
		// A token minted before the claim existed, or by an issuer that is not
		// celled. Refusing these would make setting CELL_ID a flag day that
		// invalidates every outstanding token, including ones minted seconds
		// earlier by the same process.
		{"token predates the claim", "", "us-1", false},
		{"neither", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Misdirected(tc.token, tc.serving); got != tc.want {
				t.Fatalf("Misdirected(%q, %q) = %v, want %v", tc.token, tc.serving, got, tc.want)
			}
		})
	}
}

// serve runs one request through the guard, with the cell claim already bound
// the way an auth middleware binds it after verifying the signature.
func serve(t *testing.T, serving, boundCell string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if boundCell != "" {
			c.Set(Claim, boundCell)
		}
		c.Next()
	})
	r.Use(Guard(serving, zap.NewNop()))
	r.GET("/api/v1/thing", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/thing", nil))
	return rec
}

func TestATokenFromAnotherCellIsRefusedWithTheCellThatShouldServeIt(t *testing.T) {
	rec := serve(t, "us-1", "eu-1")

	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421 (body %s)", rec.Code, rec.Body.String())
	}
	// The header is the point of the refusal. A 421 without it tells the caller
	// it guessed wrong and nothing about what would be right, which leaves
	// retrying blind as the only move.
	if got := rec.Header().Get(Header); got != "us-1" {
		t.Fatalf("%s = %q, want the serving cell %q", Header, got, "us-1")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if body["error"] != "misdirected_request" {
		t.Fatalf("error = %v, want misdirected_request", body["error"])
	}
	if body["cell"] != "us-1" {
		t.Fatalf("cell = %v, want us-1", body["cell"])
	}
}

func TestTheRightCellAndTheUncelledInstallAreServed(t *testing.T) {
	for _, tc := range []struct{ name, serving, bound string }{
		{"same cell", "eu-1", "eu-1"},
		{"no CELL_ID: every install today", "", "eu-1"},
		{"token carries no cell", "eu-1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(t, tc.serving, tc.bound)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get(Header); got != "" {
				t.Fatalf("%s = %q on a served request; the header belongs on the refusal", Header, got)
			}
		})
	}
}
