// Root build script — version catalog and shared plugin declarations live
// here so each module declares only the plugins it actually applies.
plugins {
    id("com.android.application") version "8.5.0" apply false
    id("com.android.library")     version "8.5.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.24" apply false
    // Hilt / KSP are wired in the build but no module currently has an
    // @HiltAndroidApp class. Keeping them as `apply false` declarations so
    // the next module that introduces DI can flip them on without editing
    // root files; the actual hilt + ksp plugin application is deferred to
    // the module that needs it.
    // id("com.google.devtools.ksp") version "1.9.24-1.0.20" apply false
    // id("com.google.dagger.hilt.android") version "2.51.1" apply false
}

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}
