# `OidxZiti` — embedded OpenZiti endpoint (Expo local native module)

Makes the OpenIDX app a first-class OpenZiti identity so `reach_mode=ziti`
connections can be dialed over the overlay from the device, and posture-bound
private access works without a VPN.

This is a **local Expo module** (autolinked from `modules/` during prebuild).
It wraps the OpenZiti mobile SDKs:

- **iOS** — [`CZiti`](https://github.com/openziti/ziti-sdk-swift) (CocoaPods), `ios/OidxZitiModule.swift`
- **Android** — [`org.openziti:ziti-android`](https://github.com/openziti/ziti-sdk-android), `android/.../OidxZitiModule.kt`

TS surface: `index.ts` (loaded optionally by `src/features/ziti/native.ts`), methods:
`enroll(jwt)`, `status()`, `serviceAvailable(name)`, `dial(name)`.

## Why it isn't built in the JS-only bundle
Native SDKs can't run in Expo Go or a JS-only build. Until this module is
compiled into a **dev-client / EAS build**, `requireOptionalNativeModule('OidxZiti')`
returns `null` and the app runs with overlay features disabled (enrollment +
posture still work — they're pure HTTP against the backend).

## Build steps (EAS / local prebuild)
1. **Pin SDK versions** — set the exact `CZiti` pod version in `ios/OidxZiti.podspec`
   and the `org.openziti:ziti-android` version in `android/build.gradle`, then verify
   the calls marked `MARK: SDK` (Swift) / `SDK:` (Kotlin) against those versions.
2. **Prebuild** — `npx expo prebuild` (generates ios/android projects; the local
   module autolinks via its `expo-module.config.json`).
3. **Build** — `eas build --profile development` (iOS simulator/device, Android).
   Not possible in a headless/CI-only env without the native toolchains.

## Remaining implementation (marked in the source)
Both `dial()` impls stop at the point where a Ziti connection must be bridged to
a **local `127.0.0.1` loopback socket** that the in-app WebView (Guacamole) or an
SSH client can connect to; the method should return that `host:port`. That
loopback-proxy accept-loop is the last piece to write once the SDK version is
pinned (it's small but SDK-API-specific).

## Prereqs shared with passkeys
The WebAuthn RP ID (passkeys) needs associated-domains (iOS) / assetlinks.json
(Android); the Ziti controller must issue enrollment JWTs for the app's
identities (already returned as `ziti_jwt` from `POST /agent/enroll/oauth`).
