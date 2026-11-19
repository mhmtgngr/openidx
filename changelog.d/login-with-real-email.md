### Fixed
- **Signing in with your real mail address works for directory users.** The
  login page says "Username or Email", but an Active Directory mapping usually
  fills the account's email from `userPrincipalName` (`name@corp.local`), and the
  address people actually type, the directory's `mail` attribute, was kept
  nowhere: typing it was "invalid username or password" with no account behind
  it. The directory sync now keeps `mail` as a second sign-in address
  (`users.mail`, migration 265; the account's `email`, password reset and
  notifications are unchanged), and the lookup is layered and case-insensitive:
  the username as typed, the username ignoring case, the email, then the mail
  address, trimmed of autofill whitespace. A name always wins over anyone's
  address, and an address that two accounts share signs in as neither.
  Passwordless phone sign-in finds the person the same way. Once the new build is
  running, the next directory sync fills `mail` for existing users.
- **A directory password is checked against the account's own directory name,**
  not whatever was typed to find it. Typing an address used to send that address
  to the directory, which matches `sAMAccountName` and `userPrincipalName` but
  never `mail`.
- The failed-login audit record says whether an email or a username was typed
  (`identifier_kind`).
