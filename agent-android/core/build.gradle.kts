plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("com.google.devtools.ksp")
    id("com.google.dagger.hilt.android")
}

android {
    namespace = "com.openidx.agent.core"
    compileSdk = 34

    defaultConfig {
        minSdk = 30
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.work:work-runtime-ktx:2.9.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // OkHttp for the /agent/* protocol. Ziti SDK plugs in as a SocketFactory
    // once enrollment completes; before that, we hit OpenIDX directly over HTTPS.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")

    // TODO(phase-4-followup): wire the real Ziti Android SDK once we settle on
    // the artifact coordinates. The 0.27.5 version we tried isn't published to
    // Maven Central; openziti/ziti-sdk-android publishes via GitHub Packages
    // which requires auth in the resolution config. ZitiClient is a stub for
    // now so the rest of the build is unblocked — traffic falls back to
    // direct HTTPS until this is restored.

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    // WebRTC for Phase 4 remote control. The stream-webrtc-android fork is
    // the maintained drop-in successor to the now-archived org.webrtc:
    // google-webrtc artifact; same API, current builds.
    implementation("io.getstream:stream-webrtc-android:1.1.1")

    implementation("com.google.dagger:hilt-android:2.51.1")
    ksp("com.google.dagger:hilt-android-compiler:2.51.1")
}
