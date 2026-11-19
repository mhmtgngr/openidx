package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/orgctx"
)

// WHAT A PERSON TYPES IN "USERNAME OR EMAIL".
//
// The page says "Username or Email". For a directory user, though, users.email
// held the attribute the mapping chose (often the UPN, name@corp.local) and the
// address the person actually uses, the directory's mail attribute, was kept
// nowhere: typing it was "invalid username or password" with no user behind it
// (audit, 13 Nov 05:13: mehmet.gungor.t@... failed, mehmet.gungor signed in a
// minute later). users.mail (migration 265) is that second sign-in address.
// The lookup is layered (resolveLoginUser): username as typed, username ignoring
// case, email ignoring case, mail ignoring case; the first layer that finds
// anything decides and two hits in a layer is a refusal, never a pick.

// recordingDirectory is the directory the sign-in asks. It records the name it
// was given and accepts only the right password.
type recordingDirectory struct {
	gotUsername string
	password    string
}

func (d *recordingDirectory) AuthenticateUser(_ context.Context, _, username, password string) error {
	d.gotUsername = username
	if password != d.password {
		return errors.New("bad bind")
	}
	return nil
}
func (d *recordingDirectory) ChangePassword(context.Context, string, string, string, string) error {
	return nil
}
func (d *recordingDirectory) ResetPassword(context.Context, string, string, string) error {
	return nil
}

func setMail(t *testing.T, db *database.PostgresDB, ctx context.Context, username, mail string) {
	t.Helper()
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET mail = $2 WHERE username = $1`, username, mail); err != nil {
		t.Fatalf("set mail: %v", err)
	}
}

func TestSignInWithTheAddressAPersonActuallyUses(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	aliceID := seedAuthUser(t, db, ctx, authOrgA, "alice", "alice@corp.example", authGoodPassword)
	setMail(t, db, ctx, "alice", "Alice.Liddell@Mail.Example")
	seedAuthUser(t, db, ctx, authOrgA, "bob", "bob@corp.example", authGoodPassword)

	for _, tc := range []struct {
		name, typed string
	}{
		{"the username", "alice"},
		{"the username in another case", "ALICE"},
		{"the email", "alice@corp.example"},
		{"the email in another case", "Alice@Corp.Example"},
		{"the mail address", "alice.liddell@mail.example"},
		{"the mail address in the case it is stored", "Alice.Liddell@Mail.Example"},
		{"the mail address with autofill whitespace", "  alice.liddell@mail.example \t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := s.AuthenticateUser(orgCtx, tc.typed, authGoodPassword)
			if err != nil {
				t.Fatalf("sign in as %q: %v", tc.typed, err)
			}
			if u.ID != aliceID {
				t.Errorf("signed in as %s, want alice %s", u.ID, aliceID)
			}
		})
	}

	t.Run("a wrong password for the mail address is still refused", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgCtx, "alice.liddell@mail.example", "Wr0ng-Pass!x"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})
	t.Run("an address nobody has is refused, like an unknown name", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgCtx, "nobody@mail.example", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})
	t.Run("an empty identifier names nobody", func(t *testing.T) {
		if _, err := s.AuthenticateUser(orgCtx, "   ", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})
}

func TestSignInLookupLayersAndAmbiguity(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	carolID := seedAuthUser(t, db, ctx, authOrgA, "carol", "carol@corp.example", authGoodPassword)
	seedAuthUser(t, db, ctx, authOrgA, "dave", "dave@corp.example", authGoodPassword)

	t.Run("someone's mail address cannot take over another account's username", func(t *testing.T) {
		// dave's mail is literally carol's username. Typing "carol" is carol.
		setMail(t, db, ctx, "dave", "carol")
		u, err := s.AuthenticateUser(orgCtx, "carol", authGoodPassword)
		if err != nil || u.ID != carolID {
			t.Fatalf("typing carol: user=%v err=%v, want carol", u, err)
		}
		setMail(t, db, ctx, "dave", "")
	})

	t.Run("an email that is another account's mail address signs in as neither", func(t *testing.T) {
		// An unverified or locally provisioned email that happens to be a
		// directory person's mailbox must not capture it, and the directory
		// person must not win it either: refused, audited, never a pick.
		setMail(t, db, ctx, "carol", "dave@corp.example") // dave's EMAIL is carol's mail
		if _, err := s.AuthenticateUser(orgCtx, "dave@corp.example", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a contested address signed someone in: %v", err)
		}
		setMail(t, db, ctx, "carol", "")
	})

	t.Run("an account whose email and mail are the same address is one account, not two", func(t *testing.T) {
		// The OpenLDAP default maps email to mail, so both columns hold it.
		setMail(t, db, ctx, "dave", "dave@corp.example")
		u, err := s.AuthenticateUser(orgCtx, "Dave@Corp.Example", authGoodPassword)
		if err != nil || u == nil || u.UserName != "dave" {
			t.Fatalf("an account with email == mail: user=%v err=%v", u, err)
		}
		setMail(t, db, ctx, "dave", "")
	})

	t.Run("a mail address on two accounts signs in as neither", func(t *testing.T) {
		setMail(t, db, ctx, "carol", "shared@mail.example")
		setMail(t, db, ctx, "dave", "SHARED@mail.example")
		if _, err := s.AuthenticateUser(orgCtx, "shared@mail.example", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a shared address signed someone in: %v", err)
		}
		// Each account is still reachable by its own name.
		if _, err := s.AuthenticateUser(orgCtx, "carol", authGoodPassword); err != nil {
			t.Fatalf("carol by name: %v", err)
		}
	})

	t.Run("two usernames that differ only in case: exact wins, the loose spelling is refused", func(t *testing.T) {
		upper := seedAuthUser(t, db, ctx, authOrgA, "Erin", "erin-upper@corp.example", authGoodPassword)
		seedAuthUser(t, db, ctx, authOrgA, "erin", "erin-lower@corp.example", authGoodPassword)
		u, err := s.AuthenticateUser(orgCtx, "Erin", authGoodPassword)
		if err != nil || u.ID != upper {
			t.Fatalf("typing Erin exactly: user=%v err=%v, want the capitalised account", u, err)
		}
		if _, err := s.AuthenticateUser(orgCtx, "ERIN", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("an ambiguous spelling signed someone in: %v", err)
		}
	})

	t.Run("another organization's address is not found", func(t *testing.T) {
		seedAuthUser(t, db, ctx, authOrgB, "frank", "frank@corp.example", authGoodPassword)
		setMail(t, db, ctx, "frank", "frank@mail.example")
		if _, err := s.AuthenticateUser(orgCtx, "frank@mail.example", authGoodPassword); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a mail address of another tenant signed in: %v", err)
		}
	})

	t.Run("a disabled account is refused by its mail address too", func(t *testing.T) {
		seedAuthUser(t, db, ctx, authOrgA, "gone", "gone@corp.example", authGoodPassword)
		setMail(t, db, ctx, "gone", "gone@mail.example")
		if _, err := db.Pool.Exec(ctx, `UPDATE users SET enabled = false WHERE username = 'gone'`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AuthenticateUser(orgCtx, "gone@mail.example", authGoodPassword); !errors.Is(err, ErrAccountDisabled) {
			t.Fatalf("got %v, want ErrAccountDisabled", err)
		}
	})
}

// A directory user is found by whatever address was typed, but the DIRECTORY is
// asked with the name it knows the account by (the sync's users.username,
// sAMAccountName). It used to be asked with the typed value, and an Active
// Directory search matches sAMAccountName and userPrincipalName, never mail.
func TestDirectoryUserSignsInByAddressButTheDirectoryIsAskedByItsOwnName(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})

	dirID := uuid.NewString()
	var id string
	if err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (username, email, password_hash, source, directory_id, org_id)
		VALUES ('mgungor', 'mgungor@corp.local', '', 'ldap', $1, $2) RETURNING id`, dirID, authOrgA).Scan(&id); err != nil {
		t.Fatal(err)
	}
	setMail(t, db, ctx, "mgungor", "mehmet.gungor.t@example.org")

	dir := &recordingDirectory{password: authGoodPassword}
	s.SetDirectoryService(dir)

	for _, typed := range []string{"mgungor", "mgungor@corp.local", "Mehmet.Gungor.T@Example.org"} {
		dir.gotUsername = ""
		u, err := s.AuthenticateUser(orgCtx, typed, authGoodPassword)
		if err != nil || u.ID != id {
			t.Fatalf("typing %q: user=%v err=%v", typed, u, err)
		}
		if dir.gotUsername != "mgungor" {
			t.Errorf("typing %q asked the directory for %q, want its own name %q", typed, dir.gotUsername, "mgungor")
		}
	}
	if _, err := s.AuthenticateUser(orgCtx, "mehmet.gungor.t@example.org", "Wr0ng-Pass!x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a rejected bind signed in: %v", err)
	}
}

func TestFindUserByLoginIdentifierServesThePasswordlessLookup(t *testing.T) {
	s, db, ctx := newAuthTestService(t)
	orgCtx := orgctx.With(ctx, orgctx.Org{ID: authOrgA})
	id := seedAuthUser(t, db, ctx, authOrgA, "gina", "gina@corp.example", authGoodPassword)
	setMail(t, db, ctx, "gina", "gina.g@mail.example")

	for _, typed := range []string{"gina", "GINA@corp.example", " gina.g@mail.example "} {
		u, err := s.FindUserByLoginIdentifier(orgCtx, typed)
		if err != nil || u == nil || u.ID != id {
			t.Errorf("FindUserByLoginIdentifier(%q) = %v, %v; want gina", typed, u, err)
		}
	}
	if _, err := s.FindUserByLoginIdentifier(orgCtx, "nobody@mail.example"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("an unknown identifier: %v, want ErrInvalidCredentials", err)
	}
	if _, err := s.FindUserByLoginIdentifier(ctx, "gina"); err == nil {
		t.Error("no organization in the context found a user")
	}
}
