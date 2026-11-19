package migrations

// Migration 265: the address a person signs in with, besides the account name.
//
// The login page says "Username or Email" and the server matches both, but for
// a person synced from a directory the email column holds whatever the
// attribute mapping puts there. Active Directory setups map email to
// userPrincipalName (the account is found by sAMAccountName and the mailbox may
// be empty or on another domain), so users.email was name@corp.local and the
// address a person actually uses, the mail attribute, was kept nowhere. Typing
// it got "invalid username or password" without even a user lookup behind it.
//
//   - users.mail: the directory's mail attribute, a second sign-in address.
//     Not unique and not the account's email: a shared mailbox may belong to
//     two accounts (the sign-in refuses an address that names two people), and
//     password reset and notifications keep using users.email.
//   - lower() indexes on (org_id, username), (org_id, email) and (org_id, mail):
//     the sign-in lookup is case-insensitive, and a person's mail client
//     capitalizes what it likes.
//
// Nothing is backfilled: the next directory sync fills users.mail.

var userMailUp = `-- Migration 265: a second sign-in address for directory users.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mail VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_users_org_lower_username ON users (org_id, lower(username));
CREATE INDEX IF NOT EXISTS idx_users_org_lower_email ON users (org_id, lower(email));
CREATE INDEX IF NOT EXISTS idx_users_org_lower_mail ON users (org_id, lower(mail)) WHERE mail IS NOT NULL;
`

var userMailDown = `-- Rollback migration 265.
DROP INDEX IF EXISTS idx_users_org_lower_mail;
DROP INDEX IF EXISTS idx_users_org_lower_email;
DROP INDEX IF EXISTS idx_users_org_lower_username;
ALTER TABLE users DROP COLUMN IF EXISTS mail;
`
