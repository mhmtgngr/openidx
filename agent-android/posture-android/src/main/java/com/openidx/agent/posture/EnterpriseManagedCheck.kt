package com.openidx.agent.posture

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonPrimitive

/**
 * Replaces domain_joined.go on Android. Reports whether the agent is acting
 * as Device Owner or Profile Owner — i.e. the device was provisioned through
 * Android Enterprise rather than side-installed. Severity is medium because
 * BYOD-style installs are valid in some scenarios (the server-side policy
 * decides whether non-managed devices are acceptable).
 */
class EnterpriseManagedCheck(
    private val context: Context,
    private val adminComponent: ComponentName,
) : PostureCheck {

    override val checkType: String = "enterprise_managed"
    override val defaultSeverity: String = "medium"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val pkg = context.packageName
        val isDeviceOwner = dpm.isDeviceOwnerApp(pkg)
        val isProfileOwner = dpm.isProfileOwnerApp(pkg)
        val pass = isDeviceOwner || isProfileOwner
        val role = when {
            isDeviceOwner -> "device_owner"
            isProfileOwner -> "profile_owner"
            else -> "unmanaged"
        }
        return PostureCheck.CheckOutcome(
            status = if (pass) PostureCheck.Status.PASS else PostureCheck.Status.WARN,
            score = if (pass) 1.0 else 0.5,
            message = "Management role: $role",
            details = mapOf(
                "role" to JsonPrimitive(role),
                "admin_component" to JsonPrimitive(adminComponent.flattenToShortString()),
            ),
        )
    }
}
