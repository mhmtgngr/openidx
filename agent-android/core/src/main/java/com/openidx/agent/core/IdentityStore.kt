package com.openidx.agent.core

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Persistent identity for an enrolled agent. Mirrors the response shape of
 * /agent/enroll and /agent/enroll/oauth on the OpenIDX access service so the
 * client can resume from any of those paths without divergent storage.
 */
@Serializable
data class AgentIdentity(
    val agentId: String,
    val deviceId: String,
    val authToken: String,
    val status: String,
    val enrollmentMethod: String,
    val serverUrl: String,
    val zitiIdentityJson: String? = null,
    val enrolledAtIso: String,
)

/**
 * Stores [AgentIdentity] inside EncryptedSharedPreferences so the auth-token
 * and Ziti identity are encrypted at rest with a per-app Android-Keystore-
 * backed master key. The identity is small JSON so we don't need a separate
 * key per field.
 */
class IdentityStore(context: Context) {

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

    fun save(identity: AgentIdentity) {
        prefs.edit().putString(KEY_IDENTITY, json.encodeToString(AgentIdentity.serializer(), identity)).apply()
    }

    fun load(): AgentIdentity? {
        val raw = prefs.getString(KEY_IDENTITY, null) ?: return null
        return runCatching { json.decodeFromString(AgentIdentity.serializer(), raw) }.getOrNull()
    }

    fun clear() {
        prefs.edit().remove(KEY_IDENTITY).apply()
    }

    fun isEnrolled(): Boolean = prefs.contains(KEY_IDENTITY)

    private companion object {
        const val PREFS_FILE = "openidx_agent_identity"
        const val MASTER_KEY_ALIAS = "openidx_agent_master_key"
        const val KEY_IDENTITY = "identity_v1"
        val json = Json { ignoreUnknownKeys = true }
    }
}
