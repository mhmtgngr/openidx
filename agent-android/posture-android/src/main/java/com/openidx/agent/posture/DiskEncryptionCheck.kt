package com.openidx.agent.posture

import android.app.admin.DevicePolicyManager
import android.content.Context
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonPrimitive

/**
 * Mirrors disk_encryption.go on Android. All devices shipping with Android 10+
 * (our min SDK 30) ship with file-based encryption enabled by default — but
 * we still query DevicePolicyManager so the agent reports honestly when a
 * device is encrypted in the inactive-default state (e.g. before first
 * unlock on a freshly provisioned device).
 */
class DiskEncryptionCheck(
    private val context: Context,
) : PostureCheck {

    override val checkType: String = "disk_encryption"
    override val defaultSeverity: String = "high"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val statusCode = dpm.storageEncryptionStatus
        val (pass, label) = when (statusCode) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> true to "active"
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING -> false to "activating"
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> false to "inactive"
            DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> false to "unsupported"
            else -> false to "unknown"
        }
        return PostureCheck.CheckOutcome(
            status = if (pass) PostureCheck.Status.PASS else PostureCheck.Status.FAIL,
            score = if (pass) 1.0 else 0.0,
            message = "Storage encryption: $label",
            details = mapOf(
                "status_code" to JsonPrimitive(statusCode),
                "label" to JsonPrimitive(label),
            ),
        )
    }
}
