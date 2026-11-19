package directory

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

// THE ADDRESS A PERSON TYPES AT THE LOGIN PAGE IS THE MAIL ATTRIBUTE.
//
// An Active Directory mapping commonly fills users.email from
// userPrincipalName (the account is found by sAMAccountName and the UPN is
// always set). The mail attribute, the address people actually use, was then
// kept nowhere, and typing it at the login page found no account. It is kept
// as a second sign-in address, users.mail (migration 265), read whatever the
// email mapping says.

func TestMapUserEntryKeepsMailBesideAnEmailMappedToTheUPN(t *testing.T) {
	entry := &ldap.Entry{
		DN: "CN=Test User,CN=Users,DC=corp,DC=example",
		Attributes: []*ldap.EntryAttribute{
			{Name: "sAMAccountName", Values: []string{"tuser"}},
			{Name: "userPrincipalName", Values: []string{"tuser@corp.example"}},
			{Name: "mail", Values: []string{"  Test.User@Mail.Example "}},
		},
	}
	rec := MapUserEntry(entry, AttributeMapping{Username: "sAMAccountName", Email: "userPrincipalName"})
	if rec.Email != "tuser@corp.example" || rec.Username != "tuser" {
		t.Errorf("email/username changed: %+v", rec)
	}
	if rec.Mail != "Test.User@Mail.Example" {
		t.Errorf("Mail = %q, want the trimmed mail attribute", rec.Mail)
	}
}

func TestMapUserEntryMailAttributeIsConfigurable(t *testing.T) {
	entry := &ldap.Entry{
		DN: "uid=a,dc=x",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{"a"}},
			{Name: "mail", Values: []string{"wrong@x.example"}},
			{Name: "workMail", Values: []string{"right@x.example"}},
		},
	}
	rec := MapUserEntry(entry, AttributeMapping{Username: "uid", Email: "mail", Mail: "workMail"})
	if rec.Mail != "right@x.example" {
		t.Errorf("Mail = %q, want the configured attribute", rec.Mail)
	}
	if got := MapUserEntry(&ldap.Entry{DN: "uid=b,dc=x"}, AttributeMapping{}).Mail; got != "" {
		t.Errorf("an entry with no mail attribute has Mail = %q", got)
	}
}

func TestUserAttributesAlwaysRequestMail(t *testing.T) {
	count := func(attrs []string, name string) int {
		n := 0
		for _, a := range attrs {
			if a == name {
				n++
			}
		}
		return n
	}
	// The UPN mapping: mail is not otherwise requested, and an AD search returns
	// only the attributes asked for.
	upn := NewLDAPConnector(LDAPConfig{Host: "h", Port: 389, BaseDN: "dc=x",
		AttributeMapping: AttributeMapping{Username: "sAMAccountName", Email: "userPrincipalName"}}, zap.NewNop())
	if got := count(upn.userAttributes(), "mail"); got != 1 {
		t.Errorf("UPN mapping requests mail %d times, want once: %v", got, upn.userAttributes())
	}
	// mail already mapped to email: still once.
	plain := NewLDAPConnector(LDAPConfig{Host: "h", Port: 389, BaseDN: "dc=x",
		AttributeMapping: AttributeMapping{Username: "uid", Email: "mail"}}, zap.NewNop())
	if got := count(plain.userAttributes(), "mail"); got != 1 {
		t.Errorf("mail requested %d times, want once: %v", got, plain.userAttributes())
	}
	custom := NewLDAPConnector(LDAPConfig{Host: "h", Port: 389, BaseDN: "dc=x",
		AttributeMapping: AttributeMapping{Username: "uid", Email: "mail", Mail: "workMail"}}, zap.NewNop())
	if got := count(custom.userAttributes(), "workMail"); got != 1 {
		t.Errorf("configured mail attribute requested %d times: %v", got, custom.userAttributes())
	}
}

const userMailSchema = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS ldap_dn VARCHAR(512);
ALTER TABLE users ADD COLUMN IF NOT EXISTS mail VARCHAR(255);`

// The two writes the sync makes carry the mail address, and an entry that has
// none clears it instead of leaving a stale one.
func TestSyncWritesTheMailAddress(t *testing.T) {
	e, ctx, cleanup := bookkeepingFixture(t, "http://hris.invalid")
	if e == nil {
		return
	}
	defer cleanup()
	if _, err := e.db.Pool.Exec(ctx, userMailSchema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	rec := UserRecord{DN: "CN=T,DC=x", Username: "tuser", Email: "tuser@corp.example", Mail: "t.user@mail.example", FirstName: "T", LastName: "User"}
	if err := e.insertLDAPUser(ctx, bkDir, bkOrg, "hash", rec); err != nil {
		t.Fatalf("insert: %v", err)
	}
	read := func() (mail *string, email, source string, dir string) {
		t.Helper()
		if err := e.db.Pool.QueryRow(ctx,
			`SELECT mail, email, source, directory_id::text FROM users WHERE username = 'tuser'`).Scan(&mail, &email, &source, &dir); err != nil {
			t.Fatalf("read: %v", err)
		}
		return
	}
	mail, email, source, dir := read()
	if mail == nil || *mail != "t.user@mail.example" || email != "tuser@corp.example" || source != "ldap" || dir != bkDir {
		t.Fatalf("after insert: mail=%v email=%q source=%q dir=%q", mail, email, source, dir)
	}

	var id string
	if err := e.db.Pool.QueryRow(ctx, `SELECT id::text FROM users WHERE username = 'tuser'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	rec.Mail = "new.address@mail.example"
	if err := e.updateLDAPUser(ctx, id, bkOrg, rec); err != nil {
		t.Fatalf("update: %v", err)
	}
	if mail, _, _, _ := read(); mail == nil || *mail != "new.address@mail.example" {
		t.Fatalf("after update mail = %v", mail)
	}

	rec.Mail = ""
	if err := e.updateLDAPUser(ctx, id, bkOrg, rec); err != nil {
		t.Fatalf("update: %v", err)
	}
	if mail, _, _, _ := read(); mail != nil {
		t.Fatalf("an entry with no mail attribute left %q behind", *mail)
	}

	// A new entry with no mail attribute is NULL, not the empty string (the
	// sign-in lookup skips NULL and the index is partial on it).
	if err := e.insertLDAPUser(ctx, bkDir, bkOrg, "hash", UserRecord{DN: "CN=N,DC=x", Username: "nomail", Email: "nomail@corp.example"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var isNull bool
	if err := e.db.Pool.QueryRow(ctx, `SELECT mail IS NULL FROM users WHERE username = 'nomail'`).Scan(&isNull); err != nil || !isNull {
		t.Fatalf("mail of an entry without one: null=%v err=%v", isNull, err)
	}
}
