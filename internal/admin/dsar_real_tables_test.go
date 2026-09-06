package admin

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"testing"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// TestDSAR_AgainstTheRealSchema drives both halves of the subject-rights
// implementation against a migrated database.
//
// Both were broken in the same way and neither could be seen from the outside.
//
// THE EXPORT (Article 15) gathers twelve categories and tolerates a failure in
// any of them: the error goes to a Debug log and the category is left out of
// the bundle. Four of the twelve named columns the schema does not have --
// audit_events.resource_type (it is target_type), mfa_totp.verified_at
// (enrolled_at), mfa_webauthn.friendly_name (name) and
// mfa_push_devices.device_type (platform/device_name/device_model) -- so the
// subject's own activity log and all three MFA enrolment records were missing
// from every data package this product has ever produced, and the response
// reported "categories: 8" as though eight were all there were.
//
// THE ERASURE (Article 17) opens by anonymising the user row, and that
// statement set phone_number and avatar_url, neither of which exists on users.
// It is the FIRST statement and its error is returned, so every erasure request
// has aborted before wiping a single session, MFA enrolment or consent. The
// right to erasure has never once run to completion.
func TestDSAR_AgainstTheRealSchema(t *testing.T) {
	db, cleanup := setupPAMTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	seedCtx := orgctx.WithBypassRLS(context.Background())

	const (
		org     = "00000000-0000-0000-0000-000000000010" // seeded default org
		subject = "44444444-0000-0000-0000-0000000000d1"
	)
	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := db.Pool.Exec(seedCtx, q, args...); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}

	exec(`INSERT INTO users (id, username, email, first_name, last_name, org_id)
	      VALUES ($1, 'dsar-subject', 'dsar-subject@test.local', 'Dee', 'Sar', $2)`, subject, org)
	exec(`INSERT INTO sessions (id, user_id, client_id, org_id, expires_at, ip_address)
	      VALUES (gen_random_uuid(), $1, 'console', $2, NOW() + INTERVAL '1 hour', '10.0.0.7')`, subject, org)
	exec(`INSERT INTO user_consents (user_id, consent_type, granted, org_id)
	      VALUES ($1, 'marketing', true, $2)`, subject, org)
	exec(`INSERT INTO audit_events (id, event_type, category, action, outcome, actor_id, target_id, target_type, details, created_at, org_id)
	      VALUES (gen_random_uuid(), 'authentication', 'security', 'login', 'success', $1, $1, 'user', '{}', NOW(), $2)`, subject, org)
	exec(`INSERT INTO access_requests (id, requester_id, resource_type, resource_id, resource_name, status, org_id)
	      VALUES (gen_random_uuid(), $1, 'application', gen_random_uuid(), 'Payroll', 'pending', $2)`, subject, org)
	exec(`INSERT INTO mfa_totp (user_id, secret, enabled, org_id) VALUES ($1, 'SEED', true, $2)`, subject, org)
	exec(`INSERT INTO mfa_webauthn (user_id, credential_id, public_key, name, org_id)
	      VALUES ($1, 'cred-1', 'pk-1', 'Yubikey at desk', $2)`, subject, org)
	exec(`INSERT INTO mfa_push_devices (user_id, device_token, platform, device_name, org_id)
	      VALUES ($1, 'tok-1', 'ios', 'Dee''s phone', $2)`, subject, org)

	ctx := orgctx.With(context.Background(), orgctx.Org{ID: org})
	svc := &Service{db: db, logger: zap.NewNop()}

	t.Run("the export names every category the schema can answer", func(t *testing.T) {
		res, err := svc.executeDSARExport(ctx,
			&DataSubjectRequest{ID: "55555555-0000-0000-0000-0000000000d1", UserID: subject, RequestType: "export"},
			"")
		if err != nil {
			t.Fatalf("executeDSARExport: %v", err)
		}
		path, _ := res["file_path"].(string)
		if path == "" {
			t.Fatal("no export file path in the result")
		}
		defer os.Remove(path)

		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open export: %v", err)
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("gunzip export: %v", err)
		}
		var bundle map[string]json.RawMessage
		if err := json.NewDecoder(gz).Decode(&bundle); err != nil {
			t.Fatalf("decode export: %v", err)
		}

		// The four sections that no data package has ever carried. Each is
		// asserted non-empty, because a category present as [] is the same
		// silence in a different shape.
		for _, key := range []string{"audit_events", "mfa_totp", "mfa_webauthn", "mfa_push_devices"} {
			raw, ok := bundle[key]
			if !ok {
				t.Errorf("%s: missing from the subject's data package", key)
				continue
			}
			var rows []map[string]interface{}
			if err := json.Unmarshal(raw, &rows); err != nil {
				t.Errorf("%s: %v", key, err)
				continue
			}
			if len(rows) == 0 {
				t.Errorf("%s: exported as empty though the subject has one", key)
			}
		}
		// And the ones that always worked still do.
		for _, key := range []string{"profile", "sessions", "consents", "access_requests"} {
			if _, ok := bundle[key]; !ok {
				t.Errorf("%s: missing from the subject's data package", key)
			}
		}

		// An incomplete package must say so rather than look complete.
		if failed, ok := res["categories_failed"].(int); !ok {
			t.Error("the result does not report how many categories failed")
		} else if failed != 0 {
			t.Errorf("categories_failed = %d against a schema that can answer all of them", failed)
		}
	})

	t.Run("the erasure runs to completion", func(t *testing.T) {
		if _, err := svc.executeDSARDelete(ctx,
			&DataSubjectRequest{ID: "55555555-0000-0000-0000-0000000000d2", UserID: subject, RequestType: "delete"},
			""); err != nil {
			t.Fatalf("executeDSARDelete: %v", err)
		}

		var email, first string
		var enabled bool
		if err := db.Pool.QueryRow(seedCtx,
			`SELECT email, first_name, enabled FROM users WHERE id = $1`, subject).
			Scan(&email, &first, &enabled); err != nil {
			t.Fatalf("read back the anonymised user: %v", err)
		}
		if first != "Deleted" || enabled {
			t.Errorf("user row not anonymised: first_name=%q enabled=%v", first, enabled)
		}
		if email == "dsar-subject@test.local" {
			t.Error("the subject's email survived the erasure")
		}

		// Everything that identifies the subject is gone. Before the fix none
		// of this ran at all: the first statement failed and the function
		// returned.
		for _, table := range []string{
			"sessions", "user_consents", "mfa_totp", "mfa_webauthn", "mfa_push_devices",
		} {
			var n int
			if err := db.Pool.QueryRow(seedCtx,
				`SELECT COUNT(*) FROM `+table+` WHERE user_id = $1`, subject).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			if n != 0 {
				t.Errorf("%s: %d row(s) survived the erasure", table, n)
			}
		}
	})
}
