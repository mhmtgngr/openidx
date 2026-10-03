package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// UseAs is Use for a secret a person chose, so it asks for the person's `use`
// grant. Use itself asks for none: its callers decide access on something
// else (a PAM entry names its own secret). The cloud JIT broker took the
// secret id from the request and called Use, so any member could spend any
// of the organization's secrets. These are the two halves of the grant.
func TestUseAsRequiresTheUseGrant(t *testing.T) {
	db := vaultTestDB(t)
	if db == nil {
		return
	}
	ring, err := newKeyring("", 1, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err != nil || ring == nil {
		t.Fatalf("key ring: %v (ring=%v) — this test must not silently skip", err, ring)
	}
	s, err := NewService(db, ring, nil, time.Minute, zap.NewNop())
	if err != nil {
		t.Fatalf("vault service: %v", err)
	}

	orgCtx := orgctx.With(context.Background(), orgctx.Org{ID: testOrg})
	bypass := orgctx.WithBypassRLS(orgCtx)
	user := func(name string) string {
		t.Helper()
		var id string
		if err := db.Pool.QueryRow(bypass, `
			INSERT INTO users (org_id, username, email, enabled)
			VALUES ($1::uuid, $2, $3, true) RETURNING id::text`,
			testOrg, name+"-use-as", name+"-use-as@example.test").Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", name, err)
		}
		return id
	}
	owner := user("owner")
	userGrant := user("user-grant")
	revealOnly := user("reveal-only")
	lapsed := user("lapsed")
	stranger := user("stranger")

	meta, err := s.Store(orgCtx, StoreInput{Name: "use-as-broker", Type: "generic",
		Value: []byte("broker-credential"), CreatedBy: owner, OwnerID: owner})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	for _, g := range []Grant{
		{SecretID: meta.ID, PrincipalType: "user", PrincipalID: userGrant, Actions: []string{"use"}},
		{SecretID: meta.ID, PrincipalType: "user", PrincipalID: revealOnly, Actions: []string{"reveal"}},
		{SecretID: meta.ID, PrincipalType: "user", PrincipalID: lapsed, Actions: []string{"use"}, ExpiresAt: &past},
	} {
		if _, err := s.AddGrant(orgCtx, g); err != nil {
			t.Fatalf("grant %+v: %v", g, err)
		}
	}

	for _, tc := range []struct {
		name      string
		ctx       context.Context
		org       string
		principal string
		isAdmin   bool
		wantErr   error // nil means the plaintext comes back
		anyErr    bool  // refused with an error other than the vault's own
	}{
		{"a use grant uses the secret", bypass, testOrg, userGrant, false, nil, false},
		{"an administrator uses it without a grant", bypass, testOrg, stranger, true, nil, false},
		{"a reveal grant is not a use grant", bypass, testOrg, revealOnly, false, ErrForbidden, false},
		{"a lapsed use grant is refused", bypass, testOrg, lapsed, false, ErrForbidden, false},
		{"no grant is refused", bypass, testOrg, stranger, false, ErrForbidden, false},
		{"no person is refused, administrator or not", bypass, testOrg, "", true, ErrForbidden, false},
		{"the grant is read in the organization named, not another", bypass, "00000000-0000-0000-0000-0000000000e4", userGrant, false, ErrForbidden, false},
		{"a request-scoped context is refused outright", orgCtx, testOrg, userGrant, false, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pt, err := s.UseAs(tc.ctx, tc.org, meta.ID, tc.principal, nil, tc.isAdmin, "test")
			defer zero(pt)
			switch {
			case tc.anyErr:
				if err == nil {
					t.Fatal("UseAs ran without a bypass context")
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if pt != nil {
					t.Fatal("a refusal returned plaintext")
				}
			default:
				if err != nil {
					t.Fatalf("UseAs: %v", err)
				}
				if string(pt) != "broker-credential" {
					t.Fatalf("plaintext = %q", pt)
				}
			}
		})
	}

	var n int
	if err := db.Pool.QueryRow(bypass, `
		SELECT count(*) FROM vault_checkouts
		 WHERE secret_id = $1::uuid AND mode = 'use' AND principal_id = ANY($2::uuid[]) AND reason = 'test'`,
		meta.ID, []string{userGrant, stranger}).Scan(&n); err != nil {
		t.Fatalf("count checkouts: %v", err)
	}
	if n != 2 {
		t.Errorf("checkout ledger holds %d use(s) naming the person, want 2", n)
	}
}
