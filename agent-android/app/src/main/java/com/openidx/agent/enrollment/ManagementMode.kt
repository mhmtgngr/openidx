package com.openidx.agent.enrollment

import android.app.admin.DevicePolicyManager
import android.content.Context

/**
 * Resolves the device's current Android Enterprise management posture
 * into the canonical enum the server stores in
 * enrolled_agents.management_mode.
 *
 *   device_owner   — fully managed device (QR / factory-reset provisioned)
 *   profile_owner  — managed work profile on a personal device (BYOD)
 *   unmanaged      — app installed without device-admin privileges
 *
 * Mirrors the server-side normalizeManagementMode enum; keep the three
 * string values in sync with /internal/access/agent_api.go.
 */
object ManagementMode {
    const val DEVICE_OWNER = "device_owner"
    const val PROFILE_OWNER = "profile_owner"
    const val UNMANAGED = "unmanaged"

    fun resolve(context: Context): String {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val pkg = context.packageName
        return when {
            dpm.isDeviceOwnerApp(pkg) -> DEVICE_OWNER
            dpm.isProfileOwnerApp(pkg) -> PROFILE_OWNER
            else -> UNMANAGED
        }
    }

    fun isDeviceOwner(context: Context): Boolean = resolve(context) == DEVICE_OWNER
    fun isProfileOwner(context: Context): Boolean = resolve(context) == PROFILE_OWNER
}
