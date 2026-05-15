package com.openidx.agent.admin

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.util.Log
import com.openidx.agent.enrollment.QrEnrollmentBootstrapper
import com.openidx.agent.service.OpenIDXAgentService

/**
 * Receives device-admin lifecycle events. Two flows matter here:
 *
 *  1. **Android Enterprise QR provisioning** — when the device finishes
 *     factory-reset setup with our QR, the platform calls
 *     [onProfileProvisioningComplete] and hands us the admin-extras bundle
 *     embedded in the QR. We extract the OpenIDX server URL + enrollment
 *     token and hand off to [QrEnrollmentBootstrapper] which runs the
 *     /agent/enroll call and persists the resulting identity.
 *
 *  2. **DEVICE_ADMIN_ENABLED** — fired when the user (BYOD) manually
 *     activates the admin app. We just log it; enrollment happens through
 *     [com.openidx.agent.ui.EnrollmentActivity] in the OAuth path.
 */
class OpenIDXDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Log.i(TAG, "OpenIDX device admin enabled")
    }

    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        super.onProfileProvisioningComplete(context, intent)
        val extras: PersistableBundle? =
            intent.getParcelableExtra(Intent.EXTRA_USER) // future profile owner
                ?: intent.extras?.getParcelable(
                    "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE",
                    PersistableBundle::class.java,
                )

        val serverUrl = extras?.getString(EXTRA_SERVER_URL).orEmpty()
        val token = extras?.getString(EXTRA_ENROLLMENT_TOKEN).orEmpty()

        if (serverUrl.isBlank() || token.isBlank()) {
            Log.w(TAG, "Provisioning bundle missing OpenIDX extras — cannot auto-enroll")
            return
        }

        QrEnrollmentBootstrapper.kickOff(context, serverUrl, token)
        // Start the foreground service immediately so the user sees the
        // "agent active" notification while enrollment completes.
        OpenIDXAgentService.start(context)
    }

    companion object {
        private const val TAG = "OpenIDXDeviceAdmin"
        const val EXTRA_SERVER_URL = "openidx_server_url"
        const val EXTRA_ENROLLMENT_TOKEN = "openidx_enrollment_token"
    }
}
