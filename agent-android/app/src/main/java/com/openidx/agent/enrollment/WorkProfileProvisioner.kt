package com.openidx.agent.enrollment

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.os.PersistableBundle
import android.util.Log

/**
 * Launches the Android Enterprise "managed work profile" provisioning
 * flow for BYOD devices. Unlike Device-Owner provisioning (which
 * happens at factory-reset via QR), work-profile provisioning is
 * user-initiated from inside the installed app:
 *
 *   1. The user taps "Set up work profile" in EnrollmentActivity.
 *   2. We fire ACTION_PROVISION_MANAGED_PROFILE. The platform creates
 *      a separate work profile, copies our APK into it, and makes the
 *      copy the Profile Owner.
 *   3. The PROFILE-side OpenIDXDeviceAdminReceiver receives
 *      onProfileProvisioningComplete and finishes setup
 *      (setProfileEnabled) + kicks off OAuth enrollment.
 *
 * The personal side of the device (this activity's process) just gets
 * the RESULT_OK / RESULT_CANCELED back; the actual agent lives in the
 * work profile from here on.
 */
object WorkProfileProvisioner {

    const val REQUEST_CODE = 0xB0FE

    /**
     * Returns true if the device can host a managed work profile. False
     * on devices that already have one, or that don't support the
     * feature (very old / restricted OEM builds).
     */
    fun isSupported(activity: Activity): Boolean {
        val dpm = activity.getSystemService(Activity.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val intent = buildIntent(activity, serverUrl = "")
        // resolveActivity != null means the provisioning UI is present.
        val resolvable = intent.resolveActivity(activity.packageManager) != null
        @Suppress("DEPRECATION")
        val alreadyProvisioned = dpm.isProfileOwnerApp(activity.packageName)
        return resolvable && !alreadyProvisioned
    }

    /**
     * Fire the provisioning intent. The server URL is carried in the
     * admin-extras bundle so the work-profile-side receiver knows where
     * to enroll once provisioning completes.
     */
    fun launch(activity: Activity, serverUrl: String) {
        val intent = buildIntent(activity, serverUrl)
        if (intent.resolveActivity(activity.packageManager) == null) {
            Log.w(TAG, "managed-profile provisioning not available on this device")
            return
        }
        activity.startActivityForResult(intent, REQUEST_CODE)
    }

    private fun buildIntent(activity: Activity, serverUrl: String): Intent {
        return Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE).apply {
            putExtra(
                DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
                QrEnrollmentBootstrapper.adminComponent,
            )
            // Carry the OpenIDX server URL through to the work-profile side
            // so post-provisioning enrollment knows where to go. No
            // enrollment token here — BYOD enrolls via OAuth (the user
            // signs in), so the receiver launches EnrollmentActivity rather
            // than running the token-based bootstrapper.
            if (serverUrl.isNotBlank()) {
                putExtra(
                    DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE,
                    PersistableBundle().apply {
                        putString("openidx_server_url", serverUrl)
                        putString("openidx_provision_kind", "profile_owner")
                    },
                )
            }
            putExtra(DevicePolicyManager.EXTRA_PROVISIONING_SKIP_USER_CONSENT, false)
        }
    }

    private const val TAG = "WorkProfileProvisioner"
}
