package com.openidx.agent.enrollment

import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.util.Log
import com.openidx.agent.BuildConfig
import com.openidx.agent.admin.OpenIDXDeviceAdminReceiver
import com.openidx.agent.core.AgentIdentity
import com.openidx.agent.core.EnrollDeviceInfo
import com.openidx.agent.core.IdentityStore
import com.openidx.agent.core.ServerApi
import com.openidx.agent.core.ZitiClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.time.Instant

/**
 * Runs the QR / Device-Owner enrollment flow once the platform hands us the
 * provisioning extras bundle. Intentionally static-style entry point: it's
 * invoked from a BroadcastReceiver context where launching a coroutine
 * scope tied to lifecycle isn't available.
 */
object QrEnrollmentBootstrapper {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun kickOff(context: Context, serverUrl: String, enrollmentToken: String) {
        scope.launch {
            runCatching {
                val api = ServerApi(serverUrl)
                val device = EnrollDeviceInfo(
                    hostname = Build.MODEL,
                    os = "android",
                    arch = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
                    platform = "android",
                    form_factor = inferFormFactor(context),
                )
                val resp = api.enrollWithToken(enrollmentToken, device)

                val identity = AgentIdentity(
                    agentId = resp.agent_id,
                    deviceId = resp.device_id,
                    authToken = resp.auth_token,
                    status = resp.status,
                    enrollmentMethod = "token",
                    serverUrl = serverUrl,
                    zitiIdentityJson = resp.ziti_jwt,
                    enrolledAtIso = resp.enrolled_at.ifBlank { Instant.now().toString() },
                )
                IdentityStore(context).save(identity)

                // Set up Ziti immediately so the next config/report flow over
                // the zero-trust mesh, not direct HTTPS.
                resp.ziti_jwt?.takeIf { it.isNotBlank() }?.let { jwt ->
                    ZitiClient(context).enrollWithJwt(jwt, identityAlias = resp.agent_id)
                }

                Log.i(TAG, "QR enrollment complete: ${resp.agent_id}")
            }.onFailure { e ->
                Log.e(TAG, "QR enrollment failed", e)
            }
        }
    }

    private fun inferFormFactor(context: Context): String {
        val isTablet = context.resources.configuration.smallestScreenWidthDp >= 600
        return if (isTablet) "tablet" else "phone"
    }

    // ComponentName for the admin receiver — accessed by other parts of the
    // app for DevicePolicyManager interactions.
    val adminComponent: ComponentName
        get() = ComponentName(BuildConfig.APPLICATION_ID, OpenIDXDeviceAdminReceiver::class.java.name)

    private const val TAG = "QrEnrollment"
}
