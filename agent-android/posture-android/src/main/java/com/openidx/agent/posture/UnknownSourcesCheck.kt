package com.openidx.agent.posture

import android.content.Context
import android.content.pm.PackageManager
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/**
 * Android-only check. Reports which installed packages claim
 * REQUEST_INSTALL_PACKAGES, i.e. which apps are allowed to side-load. A
 * passing check has at most the device-default installers (Play Store, OEM
 * store). Anything else is reported in `details.unexpected_installers` for
 * the admin to triage.
 */
class UnknownSourcesCheck(
    private val context: Context,
    private val allowedInstallers: Set<String> = DEFAULT_ALLOWED,
) : PostureCheck {

    override val checkType: String = "unknown_sources"
    override val defaultSeverity: String = "high"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val pm = context.packageManager
        val installerPackages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            .filter { pkg ->
                pkg.requestedPermissions?.contains("android.permission.REQUEST_INSTALL_PACKAGES") == true
            }
            .map { it.packageName }
        val unexpected = installerPackages.filter { it !in allowedInstallers }
        val pass = unexpected.isEmpty()
        return PostureCheck.CheckOutcome(
            status = if (pass) PostureCheck.Status.PASS else PostureCheck.Status.FAIL,
            score = if (pass) 1.0 else 0.0,
            message = if (pass)
                "Only approved installers detected"
            else
                "Unexpected install sources: ${unexpected.joinToString(", ")}",
            details = mapOf(
                "unexpected_installers" to JsonArray(unexpected.map { JsonPrimitive(it) }),
                "total_installers" to JsonPrimitive(installerPackages.size),
            ),
        )
    }

    private companion object {
        val DEFAULT_ALLOWED = setOf(
            "com.android.vending",          // Google Play
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.openidx.agent",            // ourselves, for MDM-pushed installs
        )
    }
}
