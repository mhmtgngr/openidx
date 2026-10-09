# Runbook: from observe to enforce

A production install starts only when every authorization control enforces,
or while a declared observe window is open. This is how an install that has
been running in development mode, or with controls in observe mode, gets to
fully enforcing without anyone losing access by surprise.

The controls (variable names as the startup log and the console show them):

| Control | What it refuses when enforcing |
| --- | --- |
| `ACCESS_ASSIGNMENT_ENFORCE=true` | reaching an application that is not assigned to the user or one of their groups |
| `STEPUP_GATE=enforce` | a privileged-session launch or an admin write without a fresh second factor |
| `BOT_GATE=enforce` | a credential spray spread across many addresses, until it proves a human |
| `POSTURE_DEVICE_TRUST_GATE=enforce` | overlay reach from a device whose posture failed |
| `PAM_REQUIRE_ZTNA=enforce` | a privileged session that would dial its target off the overlay (needs `GUACAMOLE_ZITI_PUBLIC_URL`) |
| `ACCESS_API_REQUIRE_AUTH=true`, `ADMIN_API_REQUIRE_AUTH=true` | anonymous callers on the access and admin APIs |

## 1. Declare the window

In the services' environment (on the reference box: `~/.config/oidx/common.env`,
read by every `oidx-*` unit):

```
APP_ENV=production
ENFORCEMENT_OBSERVE_UNTIL=2026-10-23      # ≤ 30 days ahead
ACCESS_ASSIGNMENT_ENFORCE=false           # or leave unset
STEPUP_GATE=observe
BOT_GATE=observe
POSTURE_DEVICE_TRUST_GATE=observe
PAM_REQUIRE_ZTNA=observe
ACCESS_API_REQUIRE_AUTH=true              # these two have no observe mode: turn them on now
ADMIN_API_REQUIRE_AUTH=true
```

Restart the services. Each one logs `AUTHZ: observe window until … (N day(s)
left)` and one `AUTHZ: control not enforcing` line per open control. A service
that does not start prints the controls it refuses and this file's advice.

`APP_ENV=production` also requires real secrets, TLS to the database and Redis,
CSRF, no wildcard CORS or trusted proxies, and non-default Ziti and Guacamole
passwords. Fix those first; they do not have an observe mode.

## 2. Read what would have been refused

Console → **Security → Enforcement** (`GET /api/v1/admin/security-posture`).
For each control it shows the mode, the days left, and **would deny (7d)**:
how many times in the last week the control recorded a refusal it did not
carry out. The same rows are in the unified audit log under
`access.assignment.would_deny` and `pam.ztna.would_deny`.

- A would-deny count of 0 for a week: flip that control.
- A count above 0: open the audit rows, assign the application (or group) the
  people were reaching, or publish the privileged target on the overlay, then
  watch the count fall.

Do not extend the window because a count is still high; fix the assignments.
The window exists so that nobody is surprised, not so that nothing changes.

## 3. Flip

Set each control to `enforce` / `true`, remove `ENFORCEMENT_OBSERVE_UNTIL`, and
restart. The startup log reports `open_gates: 0, fully_enforcing: true` and the
console page shows every control green. Keep the audit query from step 2 as a
dashboard panel: once enforcing, the same actions appear as `access.decision.deny`.

## If the window runs out

A service started after the named day refuses with
`the observe window ended on …: set each control above to enforce`. Either flip
(step 3) or, if an application is still being assigned, declare a new window
with a date you intend to keep.
