package com.openidx.agent.posture

import android.os.Build
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonPrimitive

/**
 * Mirrors /agent/internal/checks/os_version.go on Android. The minimum API
 * level is delivered as a server-side parameter; until that wiring lands,
 * fall back to "any modern Android" — anything below the app's min SDK 30
 * can't even install the agent, so the failure mode here is upper-bound.
 */
class OsVersionCheck(
    private val minSdkInt: Int = 30,
) : PostureCheck {

    override val checkType: String = "os_version"
    override val defaultSeverity: String = "medium"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val sdk = Build.VERSION.SDK_INT
        val release = Build.VERSION.RELEASE ?: ""
        val pass = sdk >= minSdkInt
        return PostureCheck.CheckOutcome(
            status = if (pass) PostureCheck.Status.PASS else PostureCheck.Status.FAIL,
            score = if (pass) 1.0 else 0.0,
            message = if (pass)
                "Android $release (API $sdk)"
            else
                "Android $release (API $sdk) is below required $minSdkInt",
            details = mapOf(
                "sdk_int" to JsonPrimitive(sdk),
                "release" to JsonPrimitive(release),
                "min_required" to JsonPrimitive(minSdkInt),
            ),
        )
    }
}
