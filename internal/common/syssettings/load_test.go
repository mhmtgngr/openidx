package syssettings_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/openidx/openidx/internal/common/syssettings"
)

// docRow answers QueryRow with one stored settings document.
type docRow string

func (d docRow) QueryRow(context.Context, string, ...any) pgx.Row { return d }

func (d docRow) Scan(dest ...any) error {
	*(dest[0].(*[]byte)) = []byte(d)
	return nil
}

// A document saved while the Security tab carried "force logout on password
// change" still holds the key. The switch is gone -- a password change and a
// reset always end sessions -- and the document must load as before, with the
// session policy the other readers depend on intact.
func TestADocumentWithTheRetiredForceLogoutKeyLoads(t *testing.T) {
	got, err := syssettings.Load(context.Background(), docRow(`{
		"security": {
			"idle_timeout": 3600,
			"absolute_timeout": 7200,
			"force_logout_on_password_change": false,
			"max_concurrent_sessions": 3,
			"concurrent_session_strategy": "terminate_oldest"
		}
	}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sec := got.Security
	if sec.IdleTimeout == nil || *sec.IdleTimeout != 3600 || sec.AbsoluteTimeout == nil || *sec.AbsoluteTimeout != 7200 ||
		sec.MaxConcurrentSessions != 3 || sec.ConcurrentSessionStrategy != "terminate_oldest" {
		t.Fatalf("the session policy did not load: %+v", sec)
	}
}

// Zero is a setting for the two session timeouts -- the Security tab documents
// 0 as "disabled" -- so a document that sets them to zero must read differently
// from one that does not carry them, like the one migration 010 seeds.
func TestAZeroTimeoutIsNotAMissingOne(t *testing.T) {
	zero, err := syssettings.Load(context.Background(), docRow(`{"security": {"idle_timeout": 0, "absolute_timeout": 0}}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if zero.Security.IdleTimeout == nil || *zero.Security.IdleTimeout != 0 ||
		zero.Security.AbsoluteTimeout == nil || *zero.Security.AbsoluteTimeout != 0 {
		t.Errorf("timeouts set to zero loaded as %v / %v, want 0 / 0", zero.Security.IdleTimeout, zero.Security.AbsoluteTimeout)
	}
	missing, err := syssettings.Load(context.Background(), docRow(`{"security": {"session_timeout": 30}}`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if missing.Security.IdleTimeout != nil || missing.Security.AbsoluteTimeout != nil {
		t.Errorf("timeouts the document does not carry loaded as %v / %v, want nil", missing.Security.IdleTimeout, missing.Security.AbsoluteTimeout)
	}
}
