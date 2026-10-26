package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestLoginWithADeadLoginSessionSaysSo pins the code the login page acts on:
// a sign-in whose pending authorization is gone must be answered with
// login_session_expired, not the invalid_request a malformed body gets, or
// the page cannot know to drop the stored id and start over.
func TestLoginWithADeadLoginSessionSaysSo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := newLoginUITestService(t, "", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/oauth/login",
		strings.NewReader(`{"username":"u","password":"p","login_session":"gone"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	svc.handleLogin(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	if body.Error != "login_session_expired" {
		t.Fatalf("error = %q, want login_session_expired", body.Error)
	}
}
