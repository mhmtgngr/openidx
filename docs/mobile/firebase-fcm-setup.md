# Firebase Cloud Messaging (FCM) setup — push-MFA on the native client

Push-MFA number-match on the Flutter client is delivered over **FCM** (Android/Web)
and **APNs** (iOS). The code is already wired and **fail-soft**: with no Firebase
project configured, the app degrades to the self-hosted **ntfy** transport, so
everything builds and push-MFA still works over ntfy. This doc is the one-time
activation for real FCM/APNs.

## What's already in place (no action needed)

- `firebase_core` + `firebase_messaging` in `client/pubspec.yaml`.
- `client/lib/mobile/firebase_push.dart` — guarded init + token fetch.
- `client/lib/firebase_options.dart` — a **stub** that `flutterfire configure`
  overwrites. Until then `FirebasePush` stays unavailable and we use ntfy.
- `client/lib/mobile/push_token_service.dart` — prefers the FCM token, falls
  back to ntfy.
- `EngineActions.enroll` auto-registers the device as a push approver
  (FastPass); the agent redeems the push-enroll ticket minted at enrollment.

The remaining work is (a) creating the Firebase project + generating config, and
(b) pointing the server at the FCM service account.

## 1. Create the Firebase project

1. https://console.firebase.google.com → **Add project** (e.g. `openidx`).
2. Add an **Android app**: package `com.example.openidx_client` (matches
   `client/android/app/src/main/AndroidManifest.xml` — change both if you rename).
3. Add an **iOS app**: bundle id `org.tdv.openidx` (or your chosen id).

## 2. Generate the Flutter config

Install the CLIs and run from `client/`:

```bash
dart pub global activate flutterfire_cli
cd client
flutterfire configure --project=<your-firebase-project-id>
```

This **overwrites** `client/lib/firebase_options.dart` with real per-platform
options and drops `google-services.json` / `GoogleService-Info.plist` into the
generated platform dirs. Commit the regenerated `firebase_options.dart`.

> The platform folders (`client/android`, `client/ios`) are generated in CI via
> `flutter create`. `firebase_options.dart` is committed Dart, so it survives —
> and because we init with `DefaultFirebaseOptions.currentPlatform`, **no
> `google-services.json` is required to build**. For a fully native release
> build you still want the native files; add them to the release job (see §5).

## 3. iOS APNs

The iOS app is registered (`com.example.openidxClient`) and its options are in
`firebase_options.dart`, so the client fetches an FCM token on iOS. To actually
*deliver* push on iOS you still need:

1. Apple Developer → create an **APNs auth key** (.p8).
2. Firebase Console → Project Settings → Cloud Messaging → upload the .p8 (Key
   ID + Team ID).
3. Xcode: enable **Push Notifications** + **Background Modes → Remote
   notifications** capability on the Runner target (the release job must apply
   these; `flutter create` does not). On a simulator / unsigned build,
   `getToken()` returns null → the app degrades to ntfy on iOS until a signed
   build with the entitlement runs on a real device.

## 4. Server: FCM service account (HTTP v1)

The backend already speaks FCM HTTP v1 (`internal/identity/pushmfa_providers.go`)
+ APNs; it just needs credentials. In Firebase Console → Project Settings →
**Service accounts** → *Generate new private key* (JSON). Then set on the
identity-service. In config the keys live under `push_mfa`
(`internal/common/config/config.go`); the env-var forms are:

```
PUSH_MFA_FCM_CREDENTIALS_FILE=/run/secrets/openidx/fcm-service-account.json
PUSH_MFA_FCM_PROJECT_ID=<your-firebase-project-id>
```

(or in YAML: `push_mfa.fcm_credentials_file` / `push_mfa.fcm_project_id`.)

(APNs for iOS is delivered by FCM once the .p8 is uploaded in §3, so no separate
APNs config is needed server-side.)

## 5. CI / release wiring

- The debug build jobs (`client-mobile-build.yml`) build in **degraded mode**
  (no Firebase config) and stay green — the stub keeps them buildable.
- For a **release** build with real push, add a CI step (release workflow) that
  restores the native config from secrets before `flutter build`:
  - `client/android/app/google-services.json` (from a base64 secret)
  - `client/ios/Runner/GoogleService-Info.plist`
  - apply the Push Notifications entitlement on iOS.

## 6. Verify end-to-end

1. Build with real config; enroll a device (the enrolled phone auto-registers as
   a push approver — confirm a `mfa_push_devices` row with a non-empty
   `agent_id`).
2. `platform` should be `android`/`ios` and `device_token` a real FCM/APNs token
   (not `ntfy:*`).
3. Trigger a login that requires MFA → the phone receives the number-match
   prompt over FCM/APNs → approve → login proceeds.
4. Because the device is a FastPass-linked approver, push is offered **first**.

## Fallback behaviour (until the above is done)

- `firebase_options.dart` stub → `Firebase.initializeApp` throws → caught →
  `FirebasePush.available == false`.
- `PushTokenService.resolve()` returns an `ntfy:<stable-id>` token.
- The enrolled phone still registers as an approver; push-MFA prompts are
  delivered on the per-user **ntfy** topic the app already subscribes to.
