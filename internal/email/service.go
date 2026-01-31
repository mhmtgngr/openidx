package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/smtp"
	"time"

	"github.com/openidx/openidx/internal/common/database"
	"go.uber.org/zap"
)

// Service handles sending emails via SMTP with template rendering and async queue support.
type Service struct {
	host      string
	port      int
	username  string
	password  string
	from      string
	redis     *database.RedisClient
	logger    *zap.Logger
	templates *template.Template
}

// EmailMessage represents an email to be sent, used for async queue serialization.
type EmailMessage struct {
	To           string                 `json:"to"`
	Subject      string                 `json:"subject"`
	TemplateName string                 `json:"template_name"`
	Data         map[string]interface{} `json:"data"`
}

// NewService creates a new email service with the given SMTP configuration.
func NewService(host string, port int, username, password, from string, redis *database.RedisClient, logger *zap.Logger) *Service {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))

	return &Service{
		host:      host,
		port:      port,
		username:  username,
		password:  password,
		from:      from,
		redis:     redis,
		logger:    logger,
		templates: tmpl,
	}
}

// Send renders the named template with the given data and sends an HTML email synchronously.
func (s *Service) Send(ctx context.Context, to, subject, templateName string, data map[string]interface{}) error {
	var body bytes.Buffer
	if err := s.templates.ExecuteTemplate(&body, templateName+".html", data); err != nil {
		return fmt.Errorf("failed to render template %s: %w", templateName, err)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n%s",
		s.from, to, subject, body.String())

	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	if err := smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("failed to send email to %s: %w", to, err)
	}

	s.logger.Info("email sent", zap.String("to", to), zap.String("subject", subject))
	return nil
}

// SendAsync enqueues an email message for asynchronous delivery via the Redis queue.
func (s *Service) SendAsync(ctx context.Context, to, subject, templateName string, data map[string]interface{}) error {
	msg := EmailMessage{
		To:           to,
		Subject:      subject,
		TemplateName: templateName,
		Data:         data,
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal email message: %w", err)
	}

	if err := s.redis.Client.LPush(ctx, "email:queue", payload).Err(); err != nil {
		return fmt.Errorf("failed to enqueue email: %w", err)
	}

	s.logger.Info("email enqueued", zap.String("to", to), zap.String("subject", subject))
	return nil
}

// ProcessQueue continuously processes the email queue, sending emails as they arrive.
// It blocks indefinitely and should be run in a goroutine.
func (s *Service) ProcessQueue(ctx context.Context) {
	s.logger.Info("email queue processor started")

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("email queue processor stopped")
			return
		default:
		}

		result, err := s.redis.Client.BRPop(ctx, 5*time.Second, "email:queue").Result()
		if err != nil {
			if err.Error() != "redis: nil" && ctx.Err() == nil {
				s.logger.Error("failed to dequeue email", zap.Error(err))
			}
			time.Sleep(1 * time.Second)
			continue
		}

		if len(result) < 2 {
			continue
		}

		var msg EmailMessage
		if err := json.Unmarshal([]byte(result[1]), &msg); err != nil {
			s.logger.Error("failed to unmarshal email message", zap.Error(err))
			continue
		}

		if err := s.Send(ctx, msg.To, msg.Subject, msg.TemplateName, msg.Data); err != nil {
			s.logger.Error("failed to send queued email",
				zap.String("to", msg.To),
				zap.String("subject", msg.Subject),
				zap.Error(err),
			)
			continue
		}
	}
}

// SendVerificationEmail sends an email verification link to the user.
func (s *Service) SendVerificationEmail(ctx context.Context, to, userName, token, baseURL string) error {
	return s.SendAsync(ctx, to, "Verify your email", "verification", map[string]interface{}{
		"Name":  userName,
		"Token": token,
		"URL":   baseURL + "/verify-email?token=" + token,
	})
}

// SendInvitationEmail sends an invitation email on behalf of the inviter.
func (s *Service) SendInvitationEmail(ctx context.Context, to, inviterName, token, baseURL string) error {
	return s.SendAsync(ctx, to, "You've been invited to OpenIDX", "invitation", map[string]interface{}{
		"InviterName": inviterName,
		"Token":       token,
		"URL":         baseURL + "/accept-invite?token=" + token,
	})
}

// SendPasswordResetEmail sends a password reset link to the user.
func (s *Service) SendPasswordResetEmail(ctx context.Context, to, userName, token, baseURL string) error {
	return s.SendAsync(ctx, to, "Reset your password", "password-reset", map[string]interface{}{
		"Name":  userName,
		"Token": token,
		"URL":   baseURL + "/reset-password?token=" + token,
	})
}

// SendWelcomeEmail sends a welcome email to a new user.
func (s *Service) SendWelcomeEmail(ctx context.Context, to, userName string) error {
	return s.SendAsync(ctx, to, "Welcome to OpenIDX", "welcome", map[string]interface{}{
		"Name": userName,
	})
}

// generateToken generates a cryptographically random 32-byte hex-encoded token.
func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random token: %v", err))
	}
	return hex.EncodeToString(b)
}
