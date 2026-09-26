package email

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/database"
)

// The welcome mail's button linked every new user of every install to a docs
// page on a domain the project does not own, so whoever registers it would
// have been one click from each recipient. It now signs in at the install's
// own public URL, the one the verification, invitation and reset mails
// already use, and a mail sent without one carries no link at all.
func TestWelcomeEmailLinksToTheInstallOnly(t *testing.T) {
	mini := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	svc := NewService("smtp.example.test", 587, "", "", "noreply@example.test",
		&database.RedisClient{Client: rc}, zap.NewNop())
	const unowned = "openidx.io" // domain-ok: the old link, which must not come back

	queued := func(t *testing.T) map[string]interface{} {
		t.Helper()
		raw, err := rc.RPop(context.Background(), "email:queue").Result()
		if err != nil {
			t.Fatalf("no queued mail: %v", err)
		}
		var msg EmailMessage
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			t.Fatalf("decode queued mail: %v", err)
		}
		if msg.TemplateName != "welcome" {
			t.Fatalf("queued template %q, want welcome", msg.TemplateName)
		}
		return msg.Data
	}
	render := func(t *testing.T, data map[string]interface{}) string {
		t.Helper()
		var body bytes.Buffer
		if err := svc.templates.ExecuteTemplate(&body, "welcome.html", data); err != nil {
			t.Fatalf("render welcome: %v", err)
		}
		return body.String()
	}

	t.Run("the button signs in at the install", func(t *testing.T) {
		if err := svc.SendWelcomeEmail(context.Background(), "new@example.test", "Ada", "https://id.example.com/"); err != nil {
			t.Fatalf("send: %v", err)
		}
		data := queued(t)
		if data["URL"] != "https://id.example.com/login" {
			t.Errorf("queued URL %v, want https://id.example.com/login", data["URL"])
		}
		body := render(t, data)
		if !strings.Contains(body, `href="https://id.example.com/login"`) {
			t.Errorf("the rendered mail does not link to the install:\n%s", body)
		}
		if strings.Contains(body, unowned) {
			t.Errorf("the rendered mail still names the old domain")
		}
	})

	t.Run("without a public URL the mail carries no link", func(t *testing.T) {
		if err := svc.SendWelcomeEmail(context.Background(), "new@example.test", "Ada", ""); err != nil {
			t.Fatalf("send: %v", err)
		}
		data := queued(t)
		if _, ok := data["URL"]; ok {
			t.Errorf("queued a URL with no public URL to build it from: %v", data["URL"])
		}
		body := render(t, data)
		if strings.Contains(body, "href=") {
			t.Errorf("a mail with no public URL still links somewhere:\n%s", body)
		}
		if !strings.Contains(body, "Welcome, Ada!") {
			t.Errorf("the mail lost its greeting:\n%s", body)
		}
	})
}
