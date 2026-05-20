plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
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

    // Ziti Android SDK — embeds the dial side of the zero-trust mesh. Once
    // Ziti.init(applicationContext) is called by OpenIDXAgentApplication
    // and an identity is enrolled via Ziti.enrollZiti, the SDK's seamless
    // mode replaces the JVM default SocketFactory so all subsequent traffic
    // (including the OkHttp client below) routes through the overlay.
    // Published to Maven Central — no auth required.
    implementation("org.openziti:ziti-android:0.30.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
}
