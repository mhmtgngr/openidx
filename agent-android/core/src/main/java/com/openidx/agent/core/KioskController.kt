package com.openidx.agent.core

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log

/**
 * Applies a [KioskPolicy] via DevicePolicyManager. Requires the app to be
 * Device Owner — when it isn't, every operation here is a no-op and a
 * single warning is logged so admins can spot misprovisioned devices in
 * the field via posture reports.
 *
 * The controller is idempotent and cheap: it can be called on every config
 * fetch without churn because Android's lock-task package list is
 * set-replace, not set-diff.
 */
class KioskController(
    private val context: Context,
    private val adminComponent: ComponentName,
) {

    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    /**
     * Apply the supplied policy. When [policy] is null, the policy is
     * cleared (allowed packages emptied, lock task features reset). When
     * [policy] has mode='off', the controller calls [stopLockTaskIfActive]
     * on the supplied activity so the device leaves kiosk mode.
     *
     * Returns true iff at least one DevicePolicyManager call was issued —
     * the foreground service uses this to decide whether to emit a
     * "kiosk.applied" audit event after a /agent/config cycle.
     */
    fun apply(policy: KioskPolicy?, currentActivity: Activity? = null): ApplyResult {
        val isDeviceOwner = dpm.isDeviceOwnerApp(context.packageName)
        val isProfileOwner = dpm.isProfileOwnerApp(context.packageName)
        // Lock-task requires either Device Owner or Profile Owner. An
        // unmanaged install can't drive kiosk at all.
        if (!isDeviceOwner && !isProfileOwner) {
            Log.w(TAG, "kiosk apply skipped: app is neither Device Owner nor Profile Owner")
            return ApplyResult.NotManaged
        }

        val effective = policy
            ?.takeIf { it.enabled && it.mode != "off" }

        if (effective == null) {
            // Clear any previously-applied lock-task config and signal the
            // activity to exit lock-task mode if it's currently in one.
            dpm.setLockTaskPackages(adminComponent, emptyArray())
            dpm.setLockTaskFeatures(adminComponent, 0)
            currentActivity?.let { stopLockTaskIfActive(it) }
            return ApplyResult.Cleared
        }

        // single_app pins the whole device to one activity — that's a
        // Device-Owner-only capability. On a Profile Owner (BYOD work
        // profile) we can't take over the whole device, so downgrade to
        // multi_app: lock-task is scoped to the work-profile apps and the
        // user keeps their personal home screen.
        val effectiveMode = if (effective.mode == "single_app" && !isDeviceOwner) {
            Log.i(TAG, "single_app kiosk downgraded to multi_app: Profile Owner can't pin the whole device")
            "multi_app"
        } else {
            effective.mode
        }

        // Build the package list. mode=single_app whitelists the primary
        // activity's package only; mode=multi_app accepts the policy's array
        // verbatim. We always include the agent itself so it can launch the
        // kiosk launcher / exit-PIN UI.
        val packages = when (effectiveMode) {
            "single_app" -> {
                val primaryPkg = effective.primary_activity
                    .substringBefore('/')
                    .takeIf { it.isNotBlank() }
                listOfNotNull(primaryPkg, context.packageName).distinct()
            }
            else -> (effective.allowed_packages + context.packageName).distinct()
        }.toTypedArray()

        dpm.setLockTaskPackages(adminComponent, packages)
        dpm.setLockTaskFeatures(adminComponent, packLockTaskFeatures(effective.lock_task_features))

        // For single_app mode (Device Owner only), pin the configured
        // activity. multi_app mode hands off to the agent's own
        // KioskLauncherActivity which lives in the app module.
        if (effectiveMode == "single_app") {
            currentActivity?.let { startLockTaskIfNeeded(it, effective) }
        }
        return ApplyResult.Applied(packages.toList())
    }

    /** Result of a single apply() call; opaque to the caller beyond logging. */
    sealed class ApplyResult {
        /** App is neither Device Owner nor Profile Owner — kiosk impossible. */
        data object NotManaged : ApplyResult()
        data object Cleared : ApplyResult()
        data class Applied(val allowedPackages: List<String>) : ApplyResult()
    }

    /**
     * Convert the wire array of feature names into the packed int bitmask
     * DevicePolicyManager expects. Unknown names are silently dropped so
     * adding a new feature on the server doesn't break older clients.
     *
     * The `blocked_activity` server-side name maps to
     * LOCK_TASK_FEATURE_BLOCK_ACTIVITY_START_WHEN_LOCKED, which is defined
     * on DevicePolicyManager but not part of the public AGP-visible API
     * surface, so we leave it unmapped here. The server's editor still
     * accepts it on the wire; the agent just won't apply it.
     */
    private fun packLockTaskFeatures(features: List<String>): Int {
        var mask = 0
        features.forEach { name ->
            mask = mask or when (name.lowercase()) {
                "home" -> DevicePolicyManager.LOCK_TASK_FEATURE_HOME
                "notifications" -> DevicePolicyManager.LOCK_TASK_FEATURE_NOTIFICATIONS
                "global_actions" -> DevicePolicyManager.LOCK_TASK_FEATURE_GLOBAL_ACTIONS
                "system_info" -> DevicePolicyManager.LOCK_TASK_FEATURE_SYSTEM_INFO
                "keyguard" -> DevicePolicyManager.LOCK_TASK_FEATURE_KEYGUARD
                "overview" -> DevicePolicyManager.LOCK_TASK_FEATURE_OVERVIEW
                else -> 0
            }
        }
        return mask
    }

    private fun startLockTaskIfNeeded(activity: Activity, policy: KioskPolicy) {
        runCatching {
            if (policy.mode == "single_app" && policy.primary_activity.isNotBlank()) {
                // Launch the configured app in lock-task. The DPM has already
                // whitelisted it, so startLockTask succeeds even without
                // calling activity.startLockTask() directly.
                val component = ComponentName.unflattenFromString(policy.primary_activity)
                    ?: return
                val launch = Intent().apply {
                    setComponent(component)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                }
                if (context.packageManager.resolveActivity(launch, PackageManager.MATCH_DEFAULT_ONLY) != null) {
                    activity.startActivity(launch)
                }
            }
        }.onFailure { e -> Log.w(TAG, "startLockTaskIfNeeded failed", e) }
    }

    private fun stopLockTaskIfActive(activity: Activity) {
        runCatching { activity.stopLockTask() }
    }

    private companion object {
        const val TAG = "KioskController"
    }
}
