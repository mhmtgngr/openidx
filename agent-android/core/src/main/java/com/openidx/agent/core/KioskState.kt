package com.openidx.agent.core

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.json.Json

/**
 * Persists the most recently-applied [KioskPolicy] so the agent can:
 *   - Reapply policy after reboot (foreground service consults this on start).
 *   - Survive network outages — when /agent/config can't be reached we keep
 *     the cached policy in force rather than dropping the device out of
 *     kiosk mode.
 *   - Emit kiosk.entered / kiosk.exited transitions by comparing the new
 *     policy against the cached one.
 *
 * Stored in EncryptedSharedPreferences alongside the identity — the policy
 * isn't strictly sensitive, but tampering with allowed_packages on disk would
 * let a local attacker break out of kiosk mode without the server's say-so.
 */
class KioskState(context: Context) {

    private val prefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context, MASTER_KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun save(policy: KioskPolicy) {
        prefs.edit().putString(KEY_POLICY, json.encodeToString(KioskPolicy.serializer(), policy)).apply()
    }

    fun load(): KioskPolicy? {
        val raw = prefs.getString(KEY_POLICY, null) ?: return null
        return runCatching { json.decodeFromString(KioskPolicy.serializer(), raw) }.getOrNull()
    }

    fun clear() {
        prefs.edit().remove(KEY_POLICY).apply()
    }

    /**
     * Returns true if the supplied policy differs (by mode / allowed_packages
     * / primary_activity / lock_task_features) from the cached one. Used by
     * the service to decide when to emit transition audit events.
     */
    fun differsFromCached(policy: KioskPolicy?): Boolean {
        val cached = load()
        if (policy == null && cached == null) return false
        if (policy == null || cached == null) return true
        return policy.mode != cached.mode
            || policy.primary_activity != cached.primary_activity
            || policy.allowed_packages != cached.allowed_packages
            || policy.lock_task_features != cached.lock_task_features
    }

    private companion object {
        const val PREFS_FILE = "openidx_kiosk_state"
        const val MASTER_KEY_ALIAS = "openidx_agent_master_key"
        const val KEY_POLICY = "kiosk_policy_v1"
        val json = Json { ignoreUnknownKeys = true }
    }
}
