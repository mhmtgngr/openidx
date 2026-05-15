# OpenIDX Android Agent

Unified Android client for the OpenIDX endpoint-agent system. Bundles
enrollment, posture, kiosk lockdown, and remote-support in a single APK
(`com.openidx.agent`). See
[`docs/superpowers/specs/2026-05-15-android-client-design.md`](../docs/superpowers/specs/2026-05-15-android-client-design.md)
for the design.

## Modules

- `app/` — UI, manifest, foreground services, receivers
- `core/` — Identity storage, server API client, Ziti tunnel, posture interface,
  WebRTC signaling
- `posture-android/` — Android-native implementations of the posture checks

## Building

### Requirements

- JDK 17
- Android SDK 34 (`platforms;android-34` and `build-tools;34.0.0`)
- Gradle 8.7+

### First-time setup

The repo does **not** check in the Gradle wrapper binary. Generate it locally
once:

```bash
cd agent-android
gradle wrapper --gradle-version 8.7
```

After that, the usual `./gradlew` flow works:

```bash
./gradlew :app:assembleDebug
./gradlew :app:lintDebug
```

CI bypasses the wrapper by invoking a pinned Gradle distribution directly
(see `.github/workflows/ci-android.yml`), so the absence of the wrapper jar
doesn't block builds.

### Outputs

- Debug APK: `app/build/outputs/apk/debug/app-debug.apk`
- Lint report: `app/build/reports/lint-results-debug.html`

The APK is hosted by the OpenIDX access service at
`/downloads/openidx-agent.apk` after copying into
`deployments/android/openidx-agent.apk` on the server. The `agent-qr`
generator endpoint reads the file to compute the Android-Enterprise
signature checksum.

## Tests

```bash
./gradlew :core:test :posture-android:test
./gradlew :app:testDebug
```

Instrumented (emulator) tests require a running AVD; CI doesn't run them
yet (tracked in the deferred list of the design doc).

## Layout

```
agent-android/
├── settings.gradle.kts          # module list
├── build.gradle.kts             # root build config, plugin versions
├── gradle.properties            # jvmargs, parallel build, etc.
├── app/                         # main app module
├── core/                        # shared library module
└── posture-android/             # check implementations
```
