# OpenIDX Mobile — Developer Handoff

What a mobile developer needs to take this app from "code-complete in the repo"
to "installable + fully working (incl. OpenZiti)".

> **Full API + architecture guide:**
> [`docs/mobile-authenticator-developer-guide.md`](../docs/mobile-authenticator-developer-guide.md)
> — the authoritative contract for login (OAuth/PKCE), MFA (TOTP + push + passkeys),
> and app-connection (PAM/Guacamole, BrowZer, native Ziti), with verified request/
> response examples and `file:line` backend citations. Read that first; this file is
> the accounts/secrets/build handoff.
>
> **Quick start for a new developer:**
> [`docs/mobile-developer-guide-simple.md`](../docs/mobile-developer-guide-simple.md)
> — set up in 5 minutes, the endpoints by feature, and sample screen patterns.

## 1. What this is / current state
React Native + Expo (SDK 57, TypeScript, expo-router) companion app. **Feature-
complete against the live backend** and `tsc`-clean:
- OAuth PKCE login + **native passkey login** + token refresh
- MFA: passkey enroll, TOTP, step-up, push-MFA number-match approve
- Approvals inbox, My Access, notifications, biometric app-lock
- Phase 2: PAM browse/request/launch (Guacamole session in a WebView)
- Phase 3: device enrollment + posture reporting; **OpenZiti native-module
  scaffold** (`modules/ziti/`, not yet compiled)

**Not done (needs a build machine / your accounts):** compile the native
`OidxZiti` module + finish its `dial()` loopback proxy; real EAS builds; push
delivery config. Details in §5.

## 2. Access to grant the developer
- **Repo:** `mhmtgngr/openidx`, work in `mobile/`.
- **Backend/API:** already deployed at `https://openidx.tdv.org` (the reference
  box). Give them a test user login + how to reach the host (VPN / `/etc/hosts`
  for `*.tdv.org` as your other users do), or a staging backend URL.

## 3. Accounts & secrets to provide / create
| Need | For | Notes |
|---|---|---|
| **Expo account + `EXPO_TOKEN`** | EAS cloud builds (CI workflow already added) | Add `EXPO_TOKEN` as a GitHub repo secret; run `cd mobile && npx eas init` once. |
| **Apple Developer account** ($99/yr) | iOS builds, signing, TestFlight | Needed for any iOS build/distribution. |
| **Google Play Console** ($25 once) | Android distribution | APKs build without it; store/internal-track needs it. |
| **Firebase (FCM) project** | Real push-MFA delivery (Android + iOS via Expo) | Service-account JSON for FCM HTTP v1 (see §5 backend note). |
| **APNs auth key** (`.p8` + Key ID + Team ID) | iOS push | From the Apple Developer account. |

## 4. Identifiers & domain verification to set up
The app ships with these defaults (overridable per EAS profile via `app.json`
`extra` / `eas.json`):
- **API base:** `https://openidx.tdv.org`  ·  **OAuth client:** `openidx-mobile`
  (public/PKCE, already seeded)  ·  **redirect:** `openidx://oauth-callback`
  ·  **scopes:** `openid profile email offline_access`
- **Bundle id / package name:** choose real ones (currently placeholder
  `com.anonymous.openidxmobile`) and set in `app.json`.
- **WebAuthn RP ID:** backend expects **`openidx.tdv.org`**
  (`WEBAUTHN_RP_ORIGINS=https://openidx.tdv.org`). For passkeys to resolve
  natively you must host domain-association files at that domain:
  - iOS: `https://openidx.tdv.org/.well-known/apple-app-site-association`
    (webcredentials: `<TEAMID>.<bundleid>`) + `associatedDomains` in app config.
  - Android: `https://openidx.tdv.org/.well-known/assetlinks.json` (app package
    + signing-cert SHA-256).

## 5. Remaining engineering work (with pointers)
1. **Finish the OpenZiti native module** — `mobile/modules/ziti/` (see its
   `README.md`): pin the `CZiti` (iOS) + `org.openziti:ziti-android` versions,
   verify the `MARK: SDK` / `SDK:` calls, and implement the `dial()` **loopback
   proxy** (bridge the Ziti connection to a `127.0.0.1:port` the WebView/SSH
   client connects to). Everything else in `modules/ziti/` + `src/features/ziti/`
   is wired.
2. **EAS builds** — `cd mobile && npx eas init`, then trigger the **"Mobile EAS
   Build"** GitHub Action (or `eas build -p android --profile preview`).
3. **Push delivery (backend, optional)** — FCM/APNs sender exists in
   `internal/identity/pushmfa.go` (config-gated: `PushMFA.fcm_server_key`,
   `apns_*`). The **FCM path uses Google's deprecated legacy API** and needs an
   HTTP-v1 (service-account) rewrite. Until then push-approve works poll-based.
4. **Deep links** — verify `openidx://oauth-callback` (OAuth) and
   `openidx://approve/<challengeId>` (push approve) resolve on device.

## 6. Tooling the developer needs
- Node 20 + npm; the Expo CLI (via `npx expo`).
- **A Mac with Xcode** for iOS (or rely on EAS macOS builders).
- **Android Studio + a KVM-capable machine** for the Android emulator (this repo
  can't build/simulate — see the note below).
- An EAS dev-client build to run the app with native modules (Expo Go can't load
  `react-native-passkeys` or `OidxZiti`).

> This project's build host is a headless Azure Linux VM: **no macOS (iOS
> impossible) and no KVM (Android emulator unusable)**. All real builds go via
> **EAS cloud** (the CI workflow) or the developer's own Mac / KVM machine.

## 7. Docs to read
- Plan: `docs/superpowers/plans/…` (mobile app plan) — architecture + task list.
- Backend context / scenarios: `docs/remote-access-lifecycle-scenarios.md`.
- Native module: `mobile/modules/ziti/README.md`.
- API client + auth patterns to follow: `mobile/src/lib/{api,auth,oauth}.ts`
  (mirror of `web/admin-console/src/lib/{api,auth}.tsx`).
