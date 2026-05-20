package com.openidx.agent.admin

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.util.Log
import com.openidx.agent.enrollment.QrEnrollmentBootstrapper
import com.openidx.agent.service.OpenIDXAgentService
import com.openidx.agent.ui.EnrollmentActivity

/**
 * Receives device-admin lifecycle events. Three provisioning flows
 * converge on [onProfileProvisioningComplete]:
 *
 *  1. **Device Owner (QR)** — factory-reset provisioning with an
 *     embedded enrollment token. We run the token-based bootstrapper.
 *
 *  2. **Profile Owner (BYOD work profile)** — user-initiated managed-
 *     profile provisioning. No enrollment token in the bundle (the
 *     provision_kind extra says "profile_owner"); we enable the
 *     profile and launch EnrollmentActivity inside it for OAuth
 *     enrollment.
 *
 *  3. **DEVICE_ADMIN_ENABLED** — fired when the user manually activates
 *     the admin app. We just log it; enrollment happens through
 *     EnrollmentActivity in the OAuth path.
 */
class OpenIDXDeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Log.i(TAG, "OpenIDX device admin enabled")
    }

    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        super.onProfileProvisioningComplete(context, intent)
        // Bundle.getParcelable(String, Class) requires API 33; we target
        // minSdk 30, so branch on SDK and fall back to the deprecated single-
        // argument overload below it. The type cast is safe — Android
        // guarantees the bundle holds a PersistableBundle on this key.
        val extras: PersistableBundle? = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            intent.extras?.getParcelable(
                EXTRAS_BUNDLE_KEY,
                PersistableBundle::class.java,
            )
        } else {
            @Suppress("DEPRECATION")
            intent.extras?.getParcelable<PersistableBundle>(EXTRAS_BUNDLE_KEY)
        }

        val serverUrl = extras?.getString(EXTRA_SERVER_URL).orEmpty()
        val token = extras?.getString(EXTRA_ENROLLMENT_TOKEN).orEmpty()
        val provisionKind = extras?.getString(EXTRA_PROVISION_KIND).orEmpty()

        // Profile-Owner / BYOD path: no enrollment token. Finalize the
        // work profile and hand off to OAuth enrollment.
        if (provisionKind == PROVISION_KIND_PROFILE_OWNER || token.isBlank()) {
            finalizeWorkProfile(context, serverUrl)
            return
        }

        // Device-Owner / QR path: token-based enrollment.
        if (serverUrl.isBlank()) {
            Log.w(TAG, "Provisioning bundle missing server URL — cannot auto-enroll")
            return
        }
        QrEnrollmentBootstrapper.kickOff(context, serverUrl, token)
        OpenIDXAgentService.start(context)
    }

    /**
     * Complete managed-profile provisioning: enable the profile, name it,
     * and launch the in-profile EnrollmentActivity so the user can sign
     * in with OAuth. The agent then lives entirely in the work profile.
     */
    private fun finalizeWorkProfile(context: Context, serverUrl: String) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = QrEnrollmentBootstrapper.adminComponent
        runCatching {
            dpm.setProfileName(admin, "OpenIDX Work")
            dpm.setProfileEnabled(admin)
        }.onFailure { e -> Log.w(TAG, "failed to enable work profile", e) }

        val launch = Intent(context, EnrollmentActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (serverUrl.isNotBlank()) {
                putExtra(EnrollmentActivity.EXTRA_PREFILL_SERVER_URL, serverUrl)
            }
        }
        runCatching { context.startActivity(launch) }
            .onFailure { e -> Log.w(TAG, "failed to launch in-profile enrollment", e) }
    }

    companion object {
        private const val TAG = "OpenIDXDeviceAdmin"
        const val EXTRA_SERVER_URL = "openidx_server_url"
        const val EXTRA_ENROLLMENT_TOKEN = "openidx_enrollment_token"
        const val EXTRA_PROVISION_KIND = "openidx_provision_kind"
        const val PROVISION_KIND_PROFILE_OWNER = "profile_owner"
        private const val EXTRAS_BUNDLE_KEY = "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE"
    }
}
