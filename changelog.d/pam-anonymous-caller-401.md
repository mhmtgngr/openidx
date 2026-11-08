### Fixed
- **A signed-out caller on the PAM pages gets 401, not 500.** With an expired
  or missing token under development auth, `/pam/entries`, `/pam/entries/{id}`
  and `/guacamole/my-connections` answered 500 "failed to check permissions";
  they now answer 401 `authentication_required`.
