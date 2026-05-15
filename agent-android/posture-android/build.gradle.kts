plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.openidx.agent.posture"
    compileSdk = 34

    defaultConfig {
        minSdk = 30
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
    implementation(project(":core"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Play Integrity API for the integrity check.
    implementation("com.google.android.play:integrity:1.3.0")

    // Posture checks construct CheckOutcome.details with JsonPrimitive /
    // JsonArray. :core's serialization-json dep is implementation-scope
    // (intentional — keeps the core API surface minimal) so we declare our
    // own here.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
}
