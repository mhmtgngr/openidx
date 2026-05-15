package com.openidx.agent.posture

import android.content.Context
import android.provider.Settings
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/**
 * Android-only check. Reports which packages have an Accessibility Service
 * enabled. Accessibility services can read screen content and inject input,
 * so any unexpected service in this list is a high-impact finding — even
 * one legitimate-looking app could be exfiltrating sensitive content.
 */
class AccessibilityAuditCheck(
    private val context: Context,
    private val allowedPackages: Set<String> = setOf("com.openidx.agent"),
) : PostureCheck {

    override val checkType: String = "accessibility_audit"
    override val defaultSeverity: String = "medium"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ).orEmpty()
        val packages = enabled.split(':')
            .filter { it.isNotBlank() }
            .map { it.substringBefore('/') }
        val unexpected = packages.filter { it !in allowedPackages }
        val pass = unexpected.isEmpty()
        return PostureCheck.CheckOutcome(
            status = if (pass) PostureCheck.Status.PASS else PostureCheck.Status.WARN,
            score = if (pass) 1.0 else 0.5,
            message = if (pass)
                "No unexpected accessibility services"
            else
                "Unexpected accessibility services: ${unexpected.joinToString(", ")}",
            details = mapOf(
                "all_services" to JsonArray(packages.map { JsonPrimitive(it) }),
                "unexpected" to JsonArray(unexpected.map { JsonPrimitive(it) }),
            ),
        )
    }
}
