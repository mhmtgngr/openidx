# Push-MFA delivery on the native client

Push-MFA number-match prompts reach the enrolled phone over the **self-hosted
ntfy topic** the app already subscribes to. That is the whole shipped transport:
there is no Firebase SDK in `client/`, no `google-services.json` to provision,
and no Google project id compiled into the binary.

This page describes what ships, and — because the *server* half of FCM/APNs is
real and complete — what it would take to add a provider transport back if you
want one.

## What ships today

| Piece | Where | State |
| --- | --- | --- |
| Client token | `client/lib/mobile/push_token_service.dart` | Mints `ntfy:<stable-per-install-id>` and stores it in the platform keystore |
| Client delivery | the per-user ntfy topic | Subscribed by the app; see [NTFY_PUSH_NOTIFICATIONS.md](../NTFY_PUSH_NOTIFICATIONS.md) |
| Server publish | `internal/identity/pushmfa.go` (`publishChallengeToNtfy`) | Every challenge is published to the user's topic |
| Server provider send | `internal/identity/pushmfa_providers.go` | Real FCM HTTP v1 + APNs token-auth senders, **skipped** for `ntfy:`-prefixed device tokens |
| Auto-registration | `EngineActions.enroll` / the OAuth login handler | The enrolled phone becomes an approver with no extra step (FastPass) |

The `ntfy:` prefix is a contract between the client and
`sendPushNotification`: a synthetic id is not a provider token, so handing it to
FCM would fail on every single challenge. `TestSendPushNotification_SkipsProviderForNtfyTokens`
and its positive control pin both halves.

### Why not Firebase

The ratified decision (readiness guide §4, decision D1) is ntfy:

- **Self-hosted.** A Zero Trust product that requires a Google project to
  deliver its second factor has a dependency its operators cannot audit.
- **No client-side identifiers.** The FlutterFire SDK compiles an `AIza…` API
  key, an app id and a project id into every binary. They are documented as
  public, not secret — but they are still a live project id shipped in an
  open-source repo, and they name an account someone has to keep.
- **It builds everywhere.** `firebase_core` pulls the Firebase C++ SDK on
  Windows desktop, whose `cmake_minimum_required(VERSION 3.1)` is rejected by
  CMake 4 — the desktop client could not be built at all while it was a
  dependency.

## Re-enabling FCM/APNs (optional, not the default)

The server needs no changes; it already speaks FCM HTTP v1 and APNs. The work is
entirely on the client, and it is a deliberate fork rather than a flag:

1. **Deps.** Add `firebase_core` + `firebase_messaging` to `client/pubspec.yaml`.
   Exclude them from the Windows/Linux desktop builds or pin
   `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`, or the desktop configure step fails.
2. **Config.** `dart pub global activate flutterfire_cli && flutterfire configure`
   from `client/`, which generates `lib/firebase_options.dart` plus
   `google-services.json` / `GoogleService-Info.plist`. Restore the native files
   from CI secrets in the release job — do not commit them.
3. **Token source.** `PushTokenService` takes the platform name through an
   injected resolver and mints the ntfy id; add a provider-token branch that
   returns the FCM/APNs token (and keeps ntfy as the fallback when
   `getToken()` returns null — simulators and unsigned iOS builds do).
4. **iOS entitlements.** Apple Developer → APNs auth key (.p8) → upload to the
   Firebase console (Key ID + Team ID); enable **Push Notifications** and
   **Background Modes → Remote notifications** on the Runner target. `flutter
   create` does not apply these, so the release job must.
5. **Server credentials.** Point identity-service at a service account:

   ```
   PUSH_MFA_FCM_CREDENTIALS_FILE=/run/secrets/openidx/fcm-service-account.json
   PUSH_MFA_FCM_PROJECT_ID=<your-firebase-project-id>
   ```

   (YAML: `push_mfa.fcm_credentials_file` / `push_mfa.fcm_project_id`. APNs is
   delivered through FCM once the .p8 is uploaded, so no separate APNs config is
   needed.)

## Verifying delivery

1. Enroll a device. Confirm an `mfa_push_devices` row exists with a non-empty
   `agent_id` and `platform` of `android`/`ios`.
2. `device_token` is `ntfy:<32 hex chars>` on a stock build. A provider token
   means step 3 above was applied.
3. Trigger a login that requires MFA. The phone gets a tappable number-match
   prompt that deep-links into the approve screen; approving completes the login.
4. Because the device is a FastPass-linked approver, push is offered **first**
   among the user's factors.

If nothing arrives, check the ntfy topic directly before suspecting the app —
`publishChallengeToNtfy` logs `Push MFA challenge delivered via ntfy` at info on
success.
