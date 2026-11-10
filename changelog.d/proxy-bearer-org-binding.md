### Security
- **A bearer token is held to its route's organization.** On a proxied
  application (the built-in proxy and the APISIX forward-auth hook), an
  access token presented as `Authorization: Bearer` was accepted on any
  organization's route, with its roles judged there, and a machine token
  (client credentials, no user) passed a route that only required a signed-in
  caller. A bearer is now a session only for a person, and only on routes of
  the organization the token was issued in; anything else is sent to sign in.
