package access

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// /access/.auth/session is the endpoint a forward-auth consumer reads to learn
// when the session it is riding on stops being valid. The absolute expiry lives
// in the Redis blob (`expires`), createProxySession puts it on the struct, and
// handleSessionInfo reports session.ExpiresAt -- but getSessionFromRequest, the
// only reader handleSessionInfo uses, never copied the field back out. It read
// `expires` to decide whether the session was still alive and then dropped it,
// so every live session answered with the zero time.
//
// That is the same shape as the rest of this series: an answer that reads as
// authoritative while the value it names was never filled in. A client honouring
// it re-authenticates on every request; a client ignoring it never learns the
// session is about to end. Measured against a real Redis, over the real route.
func sessionInfoService(t *testing.T) (*gin.Engine, *goredis.Client) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mini := miniredis.RunT(t)
	rc := goredis.NewClient(&goredis.Options{Addr: mini.Addr()})
	svc := &Service{logger: zap.NewNop(), redis: &database.RedisClient{Client: rc}}

	router := gin.New()
	router.GET("/access/.auth/session", svc.handleSessionInfo)
	return router, rc
}

func seedProxySession(t *testing.T, rc *goredis.Client, token string, expires time.Time) {
	t.Helper()
	blob, err := json.Marshal(map[string]interface{}{
		"id":          "sess-1",
		"user_id":     "user-1",
		"email":       "someone@example.com",
		"name":        "Someone",
		"roles":       []string{"reader"},
		"expires":     expires.Unix(),
		"last_active": time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if err := rc.Set(t.Context(), "proxy_session:"+hashToken(token), blob, 12*time.Hour).Err(); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func TestSessionInfoReportsTheExpiryTheSessionActuallyHas(t *testing.T) {
	router, rc := sessionInfoService(t)
	const token = "cookie-token"
	expires := time.Now().Add(3 * time.Hour).Truncate(time.Second)
	seedProxySession(t, rc, token, expires)

	req := httptest.NewRequest(http.MethodGet, "/access/.auth/session", nil)
	req.AddCookie(&http.Cookie{Name: "_openidx_proxy_session", Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("session info = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got struct {
		UserID    string    `json:"user_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if got.UserID != "user-1" {
		t.Fatalf("user_id = %q, want user-1", got.UserID)
	}
	if got.ExpiresAt.IsZero() {
		t.Fatal("expires_at is the zero time: the endpoint reported an expiry it never read back from the session blob")
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Fatalf("expires_at = %s, want %s", got.ExpiresAt, expires)
	}
}
