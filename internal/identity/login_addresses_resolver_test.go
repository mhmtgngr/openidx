package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// loginAddressesTestSchema is user_login_addresses (migration 266) without the
// foreign keys to tables these hand-made schemas do not carry. The CHECK and the
// unique index are the real ones: they are part of what the tests rely on.
const loginAddressesTestSchema = `
CREATE TABLE user_login_addresses (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address    VARCHAR(255) NOT NULL
               CHECK (address = lower(btrim(address)) AND address LIKE '%@%'),
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_user_login_addresses_org_address ON user_login_addresses (org_id, address);
`

func addLoginAddress(t *testing.T, db *database.PostgresDB, ctx context.Context, org, userID, address string) {
	t.Helper()
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO user_login_addresses (org_id, user_id, address) VALUES ($1, $2, $3)`,
		org, userID, address); err != nil {
		t.Fatalf("add login address: %v", err)
	}
}

// AN ADDRESS AN ADMINISTRATOR GAVE THE ACCOUNT.
//
// users.mail belongs to the directory sync (it rewrites it every run) and a
// local account has no directory, so a person whose real address is in neither
// had no way to sign in with it. user_login_addresses is the administrator's
// own list, read in the same layer as email and mail: one hit is the account,
// two hits is a refusal, and a username always beats an address.
func TestSignInWithAnAddressTheAdministratorGave(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	hanaID := seedAuthUser(t, db, ctx, authOrgA, "hana", "hana@corp.example", authGoodPassword)
	seedAuthUser(t, db, ctx, authOrgA, "ivan", "ivan@corp.example", authGoodPassword)
	addLoginAddress(t, db, ctx, authOrgA, hanaID, "hana.real@company.example")

	for _, typed := range []string{
		"hana.real@company.example",
		"Hana.Real@Company.Example",
		"  hana.real@company.example\t",
	} {
		u, err := s.AuthenticateUser(orgCtx, typed, authGoodPassword)
		if err != nil || u.ID != hanaID {
			t.Errorf("signing in as %q: user=%v err=%v, want hana", typed, u, err)
		}
	}

	t.Run("it also serves the passwordless lookup", func(t *testing.T) {
		u, err := s.FindUserByLoginIdentifier(orgCtx, "hana.real@company.example")
		if err != nil || u.ID != hanaID {
			t.Fatalf("lookup: user=%v err=%v", u, err)
		}
	})

	t.Run("a wrong password for the address is still refused", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgCtx, "hana.real@company.example", "Wr0ng-Pass!x"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("an address that is also another account's email signs in as neither", func(t *testing.T) {
		// Added before ivan's email was changed to it, or typed by hand around
		// the write-time check: the sign-in must refuse, not pick.
		addLoginAddress(t, db, ctx, authOrgA, hanaID, "ivan@corp.example")
		if _, err := s.AuthenticateUser(orgCtx, "ivan@corp.example", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a contested address signed someone in: %v", err)
		}
		if _, err := db.Pool.Exec(ctx, `DELETE FROM user_login_addresses WHERE address = 'ivan@corp.example'`); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an address equal to another account's username never takes it over", func(t *testing.T) {
		// Admin tooling refuses this at write time; if it is there anyway the
		// username layer decides first.
		if _, err := db.Pool.Exec(ctx, `UPDATE users SET username = 'ivan@company.example' WHERE username = 'ivan'`); err != nil {
			t.Fatal(err)
		}
		addLoginAddress(t, db, ctx, authOrgA, hanaID, "ivan@company.example")
		u, err := s.AuthenticateUser(orgCtx, "ivan@company.example", authGoodPassword)
		if err != nil || u.UserName != "ivan@company.example" {
			t.Fatalf("username lost to an alias: user=%v err=%v", u, err)
		}
	})

	t.Run("an account whose email and alias are the same address is one account", func(t *testing.T) {
		jonID := seedAuthUser(t, db, ctx, authOrgA, "jon", "jon@corp.example", authGoodPassword)
		addLoginAddress(t, db, ctx, authOrgA, jonID, "jon@corp.example")
		u, err := s.AuthenticateUser(orgCtx, "jon@corp.example", authGoodPassword)
		if err != nil || u.ID != jonID {
			t.Fatalf("user=%v err=%v", u, err)
		}
	})

	t.Run("another organization's alias is not found", func(t *testing.T) {
		kayID := seedAuthUser(t, db, ctx, authOrgB, "kay", "kay@corp.example", authGoodPassword)
		addLoginAddress(t, db, ctx, authOrgB, kayID, "kay.real@company.example")
		if _, err := s.AuthenticateUser(orgCtx, "kay.real@company.example", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("an alias of another tenant signed in: %v", err)
		}
	})

	t.Run("a disabled account is refused by its alias too", func(t *testing.T) {
		leoID := seedAuthUser(t, db, ctx, authOrgA, "leo", "leo@corp.example", authGoodPassword)
		addLoginAddress(t, db, ctx, authOrgA, leoID, "leo.real@company.example")
		if _, err := db.Pool.Exec(ctx, `UPDATE users SET enabled = false WHERE username = 'leo'`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AuthenticateUser(orgCtx, "leo.real@company.example", authGoodPassword); !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("got %v, want ErrAccountDisabled", err)
		}
	})

	t.Run("deleting the account takes its addresses with it", func(t *testing.T) {
		mia := seedAuthUser(t, db, ctx, authOrgA, "mia", "mia@corp.example", authGoodPassword)
		addLoginAddress(t, db, ctx, authOrgA, mia, "mia.real@company.example")
		if _, err := db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, mia); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM user_login_addresses WHERE user_id = $1`, mia).Scan(&n); err != nil || n != 0 {
			t.Fatalf("addresses left behind: %d, %v", n, err)
		}
	})
}
