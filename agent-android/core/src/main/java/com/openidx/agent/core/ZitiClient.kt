package com.openidx.agent.core

import android.content.Context
import android.util.Log
import okhttp3.OkHttpClient
import org.openziti.android.Ziti

/**
 * Lifecycle wrapper over the Ziti Android SDK (`org.openziti:ziti-android`).
 *
 * The real SDK exposes a process-global [Ziti] object; this class owns the
 * tiny set of operations the agent needs and keeps the API the rest of the
 * codebase already calls (`enrollWithJwt`, `initializeFromStored`,
 * `okHttpClient`, `shutdown`) so call sites stay unchanged.
 *
 * Two design notes worth knowing when touching this code:
 *
 *  - **`Ziti.init` is process-global and required before *any* other call**.
 *    OpenIDXAgentApplication.onCreate calls it once; [initializeFromStored]
 *    is the safe re-entry point used by background workers and BootReceiver.
 *    Calling init twice is harmless (the SDK guards internally).
 *
 *  - **`seamless = true`** flips the JVM-wide default socket factory after
 *    init, so any plain `OkHttpClient()` already routes through the Ziti
 *    overlay for hosts the network advertises. The explicit
 *    [okHttpClient] below is there for callers that want to *also* attach
 *    the Ziti DNS resolver — useful for short-lived clients that don't
 *    inherit the JVM default.
 */
class ZitiClient(private val context: Context) {

    /**
     * Enroll the device into the Ziti network using the JWT returned by
     * /agent/enroll. The SDK stores the resulting identity in the Android
     * KeyStore + sharedPrefs (`ziti` file) keyed by `"ziti-sdk"`; the
     * [identityAlias] parameter is accepted for backward compatibility with
     * the stub but ignored by the SDK's enrollment routine.
     *
     * Note: [Ziti.enrollZiti] runs enrollment on a background thread inside
     * the SDK and returns immediately. Listen on [Ziti.identityEvents] if
     * you need a completion signal — for the agent we just kick it off and
     * let subsequent traffic ride the overlay once enrollment finishes.
     */
    @Suppress("UNUSED_PARAMETER")
    fun enrollWithJwt(jwt: String, identityAlias: String) {
        ensureInitialized()
        runCatching {
            Ziti.enrollZiti(jwt.toByteArray(Charsets.UTF_8))
        }.onFailure { e ->
            Log.w(TAG, "ziti enrollment failed", e)
        }
    }

    /**
     * Boot the SDK from any previously-enrolled identities. Safe to call
     * repeatedly. Required after process restart (BootReceiver / service
     * onCreate) before any traffic should ride Ziti.
     */
    fun initializeFromStored() {
        ensureInitialized()
    }

    /**
     * Returns an OkHttpClient that explicitly dials through Ziti when the
     * SDK is initialized. Callers that just want JVM-default behavior can
     * use `OkHttpClient()` directly — seamless mode (set in
     * [Ziti.init]) already replaces the global socket factory.
     */
    fun okHttpClient(): OkHttpClient {
        if (!initialized) return OkHttpClient()
        return runCatching {
            OkHttpClient.Builder()
                .socketFactory(Ziti.getSocketFactory())
                .build()
        }.getOrElse {
            Log.w(TAG, "ziti socket factory unavailable; falling back to default", it)
            OkHttpClient()
        }
    }

    /**
     * No-op kept for source compatibility with the previous stub. The Ziti
     * SDK manages its own lifecycle scoped to the Application; explicit
     * shutdown isn't part of the public API.
     */
    fun shutdown() {
        // Intentionally empty.
    }

    private fun ensureInitialized() {
        if (initialized) return
        synchronized(initLock) {
            if (initialized) return
            runCatching {
                Ziti.init(context.applicationContext, /* seamless = */ true)
                initialized = true
            }.onFailure { e ->
                Log.w(TAG, "Ziti.init failed; falling back to direct transport", e)
            }
        }
    }

    private companion object {
        const val TAG = "ZitiClient"

        // Init is process-global on the SDK side, so the "initialized"
        // flag mirrors it across all ZitiClient instances. Synchronization
        // protects against the racy first-touch from multiple components
        // (Application.onCreate + foreground service + BootReceiver) all
        // reaching for the SDK at startup.
        @Volatile private var initialized: Boolean = false
        private val initLock = Any()
    }
}
