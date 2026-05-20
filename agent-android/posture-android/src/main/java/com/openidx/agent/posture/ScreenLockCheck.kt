package com.openidx.agent.posture

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonPrimitive

/**
 * Mirrors screen_lock.go on Android. A passing check requires that the
 * keyguard is secure (PIN/pattern/password/biometric configured); we also
 * surface the password quality so admins can see when a device meets the
 * baseline but not their own policy bar.
 */
class ScreenLockCheck(private val context: Context) : PostureCheck {

    override val checkType: String = "screen_lock"
    override val defaultSeverity: String = "high"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

        val secure = km.isKeyguardSecure
        val quality = runCatching { dpm.getPasswordQuality(null) }.getOrDefault(
            DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED
        )

        return PostureCheck.CheckOutcome(
            status = if (secure) PostureCheck.Status.PASS else PostureCheck.Status.FAIL,
            score = if (secure) 1.0 else 0.0,
            message = if (secure) "Screen lock configured" else "No screen lock set",
            details = mapOf(
                "secure" to JsonPrimitive(secure),
                "password_quality" to JsonPrimitive(quality),
            ),
        )
    }
}
