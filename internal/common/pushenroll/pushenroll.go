// Package pushenroll holds the shared contract for the push-authenticator
// enrollment ticket: a single-use, short-lived token, stored in Redis, that
// authorizes binding a phone as a push-MFA device WITHOUT a separate user login.
//
// Two producers mint these tickets, one consumer redeems them:
//   - identity-service mints one from an authenticated user's console/app screen
//     (the classic "scan a QR to add this device" flow), and
//   - access-service mints one at agent-enrollment time so a freshly-enrolled
//     device can self-register as a push approver, carrying the enrollment's
//     server-verified user/org identity and its device-trust decision.
//
// identity-service's CompletePushEnrollment redeems the ticket. Keeping the key
// prefix + payload here (a leaf package with no service deps) lets both services
// share one format without an access→identity import cycle.
package pushenroll

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// KeyPrefix namespaces the Redis ticket keys.
const KeyPrefix = "push_enroll:"

// DefaultTTL is how long a ticket is bindable. Short by design: a stale ticket
// must not linger as a usable credential.
const DefaultTTL = 5 * time.Minute

// TicketData is the JSON stored in Redis against a ticket token. UserID/OrgID
// are always set. The remaining fields are populated only when the ticket
// originates from a device enrollment (access-service), linking the resulting
// push device back to the enrolled agent and conveying the enrollment's
// server-verified auto-trust decision.
type TicketData struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
	// Trusted mirrors the device-enrollment auto-trust decision. It derives from
	// a SERVER-VERIFIED enrollment session (never client-supplied); redemption
	// may mark the push device trusted only because of it.
	Trusted             bool   `json:"trusted,omitempty"`
	AgentID             string `json:"agent_id,omitempty"`
	DeviceID            string `json:"device_id,omitempty"`
	EnrollmentSessionID string `json:"enrollment_session_id,omitempty"`
}

// Mint stores a new single-use ticket for d and returns its opaque token. ttl<=0
// falls back to DefaultTTL.
func Mint(ctx context.Context, rdb *redis.Client, d TicketData, ttl time.Duration) (string, error) {
	if rdb == nil {
		return "", fmt.Errorf("push enrollment unavailable: no redis")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate enrollment token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	payload, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	if err := rdb.Set(ctx, KeyPrefix+token, string(payload), ttl).Err(); err != nil {
		return "", fmt.Errorf("failed to store enrollment ticket: %w", err)
	}
	return token, nil
}

// Peek reads (without consuming) the ticket for token. Returns an error if the
// ticket is missing or expired.
func Peek(ctx context.Context, rdb *redis.Client, token string) (TicketData, error) {
	var d TicketData
	if rdb == nil {
		return d, fmt.Errorf("push enrollment unavailable: no redis")
	}
	raw, err := rdb.Get(ctx, KeyPrefix+token).Result()
	if err != nil {
		return d, fmt.Errorf("enrollment ticket is invalid or expired")
	}
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return d, fmt.Errorf("enrollment ticket is invalid or expired")
	}
	return d, nil
}

// Consume deletes the ticket for token (single-use). Best-effort; a delete error
// is returned so callers can log it, but the ticket data must be fetched via
// Peek first.
func Consume(ctx context.Context, rdb *redis.Client, token string) error {
	if rdb == nil {
		return nil
	}
	return rdb.Del(ctx, KeyPrefix+token).Err()
}
