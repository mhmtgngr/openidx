package com.openidx.agent.posture

import android.content.Context
import android.provider.Settings
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonPrimitive

/**
 * New Android-only check (no Go-side equivalent). Developer-options-enabled
 * devices expose ADB and a much larger attack surface, so most enterprise
 * policies require it disabled unless IT explicitly opts in.
 */
class DeveloperOptionsCheck(private val context: Context) : PostureCheck {

    override val checkType: String = "developer_options"
    override val defaultSeverity: String = "medium"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val devEnabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0,
        ) == 1
        val adbEnabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0,
        ) == 1
        val pass = !devEnabled && !adbEnabled
        return PostureCheck.CheckOutcome(
            status = if (pass) PostureCheck.Status.PASS else PostureCheck.Status.FAIL,
            score = if (pass) 1.0 else 0.0,
            message = when {
                devEnabled && adbEnabled -> "Developer options + ADB enabled"
                devEnabled -> "Developer options enabled"
                adbEnabled -> "ADB enabled"
                else -> "Developer options disabled"
            },
            details = mapOf(
                "developer_options_enabled" to JsonPrimitive(devEnabled),
                "adb_enabled" to JsonPrimitive(adbEnabled),
            ),
        )
    }
}
