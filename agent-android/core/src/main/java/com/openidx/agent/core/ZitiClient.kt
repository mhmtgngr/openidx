package com.openidx.agent.core

import android.content.Context
import android.util.Log
import okhttp3.OkHttpClient

/**
 * Stubbed Ziti tunnel wrapper. The real openziti SDK isn't wired into this
 * build yet (see TODO in core/build.gradle.kts) so every operation here is a
 * no-op and [okHttpClient] returns a plain OkHttp client.
 *
 * The shape mirrors the eventual implementation so the call sites in the
 * enrollment + service code don't need to change once the SDK is restored:
 *
 *   - enrollWithJwt(jwt, alias)   — store the Ziti identity for the alias
 *   - initializeFromStored()      — boot the Ziti context from disk
 *   - okHttpClient()              — return a Ziti-tunneled OkHttp client
 *   - shutdown()                  — tear the context down
 *
 * Until the SDK is back in, [okHttpClient] returns a vanilla client so
 * /agent/* traffic continues over direct HTTPS. Posture and config flow
 * works; the only thing missing is the zero-trust overlay.
 */
class ZitiClient(private val context: Context) {

    @Suppress("UNUSED_PARAMETER")
    fun enrollWithJwt(jwt: String, identityAlias: String) {
        Log.i(TAG, "Ziti SDK not wired — enrollment recorded but no-op (alias=$identityAlias)")
    }

    fun initializeFromStored() {
        // No Ziti context yet; nothing to do.
    }

    fun okHttpClient(): OkHttpClient = OkHttpClient()

    fun shutdown() {
        // No-op until the SDK is restored.
    }

    private companion object {
        const val TAG = "ZitiClient"
    }
}
