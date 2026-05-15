package com.openidx.agent.core

import android.content.Context
import android.util.Log
import okhttp3.OkHttpClient
import org.openziti.Ziti

/**
 * Lifecycle wrapper over the Ziti Android SDK. The SDK is initialized with
 * the JWT returned by enrollment; after that, the [okHttpClient] property
 * returns a client whose socket factory dials through the Ziti overlay so
 * every subsequent request to OpenIDX traverses the zero-trust mesh.
 *
 * The class is safe to call before enrollment finishes — [okHttpClient]
 * falls back to a plain OkHttpClient when the Ziti context is unavailable
 * so the [ServerApi] can be constructed once and shared across phases.
 */
class ZitiClient(private val context: Context) {

    @Volatile private var zitiInitialized: Boolean = false

    /**
     * Enroll the device into the Ziti network using the JWT returned by
     * /agent/enroll. The SDK persists the resulting identity in its own
     * secure storage keyed by [identityAlias].
     */
    fun enrollWithJwt(jwt: String, identityAlias: String) {
        runCatching {
            // Ziti Android SDK API: enrollJwt writes the materialized identity
            // to internal storage under the supplied alias.
            Ziti.enrollZiti(jwt.toByteArray(Charsets.UTF_8), identityAlias)
            Ziti.init(context, seamless = true)
            zitiInitialized = true
        }.onFailure { e ->
            Log.w(TAG, "ziti enroll failed; running in fallback mode", e)
        }
    }

    /** Initialize Ziti from an already-enrolled identity (e.g. after reboot). */
    fun initializeFromStored() {
        if (zitiInitialized) return
        runCatching {
            Ziti.init(context, seamless = true)
            zitiInitialized = true
        }.onFailure { e ->
            Log.w(TAG, "ziti init failed", e)
        }
    }

    /**
     * Returns an OkHttpClient that dials through Ziti when initialized, or a
     * plain client otherwise. Callers should obtain a fresh instance after
     * [enrollWithJwt] returns so subsequent traffic flows over Ziti.
     */
    fun okHttpClient(): OkHttpClient {
        if (!zitiInitialized) return OkHttpClient()
        return OkHttpClient.Builder()
            .socketFactory(Ziti.getSocketFactory())
            .dns(Ziti.getDNS())
            .build()
    }

    fun shutdown() {
        runCatching { Ziti.shutdown() }
        zitiInitialized = false
    }

    private companion object {
        const val TAG = "ZitiClient"
    }
}
