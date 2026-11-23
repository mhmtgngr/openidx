# Sign-in addresses

The login page says **Username or Email**. A person can sign in with:

1. the account name (username);
2. the account's **email**, which for a directory user is whatever the attribute
   mapping puts there (often the `userPrincipalName`, `name@corp.local`);
3. the directory's **mail** attribute (`users.mail`), kept by every directory sync;
4. an address an **administrator gave the account** (below).

Case does not matter and surrounding spaces are ignored. The lookup is layered:
a username always wins over anyone's address, and an address that names two
accounts signs in as **neither** (the refusal is audited as `ambiguous_identifier`).

## Giving an account an address

Users → the account's menu → **Edit user** → **Sign-in addresses** → type the
address → **Add**. Use this when the person's real address is not in the
directory's `mail` attribute, or the account is local.

- The directory sync never changes or removes these addresses.
- Only an administrator can add or remove them, never the account holder.
- An address that is another account's username, email, mail or address is refused.
  An account can hold up to 5.
- Both changes are audited: `user.login_address_added`, `user.login_address_removed`.
- Password reset and notifications still use the account's **email**.

API: `GET|POST /api/v1/identity/users/{id}/login-addresses`,
`DELETE /api/v1/identity/users/{id}/login-addresses/{addrId}`.
