package com.openidx.agent.enrollment

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import com.openidx.agent.core.AgentIdentity
import com.openidx.agent.core.EnrollDeviceInfo
import com.openidx.agent.core.IdentityStore
import com.openidx.agent.core.ServerApi
import com.openidx.agent.core.ZitiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.openid.appauth.AuthState
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationResponse
import net.openid.appauth.AuthorizationService
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues
import java.time.Instant
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * Drives the email/OAuth enrollment path:
 *
 *   1. Launch a Chrome Custom Tab via AppAuth to OpenIDX's authorization
 *      endpoint with PKCE.
 *   2. Receive the redirect, exchange code -> access token.
 *   3. POST /agent/enroll/oauth with the access token.
 *   4. Persist the resulting identity + bootstrap Ziti.
 *
 * The OpenIDX issuer is discovered from its well-known config; the agent
 * registers as a public OAuth client with the redirect URI declared in the
 * AndroidManifest (`com.openidx.agent://oauth/redirect`).
 */
class OAuthEnrollmentFlow(
    private val activity: Activity,
    private val serverUrl: String,
    private val clientId: String = DEFAULT_CLIENT_ID,
) {

    private val authService = AuthorizationService(activity)

    /**
     * Step 1: launch the OAuth authorization request. Result is delivered to
     * [Activity.onActivityResult] / NewIntent (depending on Android version)
     * with [REQUEST_CODE].
     */
    fun launch(authorizationRequestCode: Int = REQUEST_CODE) {
        val config = AuthorizationServiceConfiguration(
            Uri.parse("$serverUrl/oauth/authorize"),
            Uri.parse("$serverUrl/oauth/token"),
        )
        val request = AuthorizationRequest.Builder(
            config,
            clientId,
            ResponseTypeValues.CODE,
            Uri.parse(REDIRECT_URI),
        )
            .setScopes("openid", "profile", "offline_access", "agent.enroll")
            .build()

        val completeIntent = Intent(activity, activity.javaClass)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pendingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE
        } else 0
        val completePI = PendingIntent.getActivity(
            activity, authorizationRequestCode, completeIntent, pendingFlags
        )
        val cancelPI = PendingIntent.getActivity(
            activity, authorizationRequestCode + 1, completeIntent, pendingFlags
        )

        authService.performAuthorizationRequest(request, completePI, cancelPI)
    }

    /**
     * Step 2-4: invoked from the activity's onCreate/onNewIntent when the
     * OAuth redirect comes back. Returns the persisted identity on success.
     */
    suspend fun handleRedirect(intent: Intent): Result<AgentIdentity> {
        val resp = AuthorizationResponse.fromIntent(intent)
            ?: return Result.failure(IllegalStateException("no authorization response in intent"))

        val tokenResp = suspendCoroutine<net.openid.appauth.TokenResponse?> { cont ->
            authService.performTokenRequest(resp.createTokenExchangeRequest()) { tr, _ ->
                cont.resume(tr)
            }
        } ?: return Result.failure(IllegalStateException("token exchange failed"))

        val accessToken = tokenResp.accessToken
            ?: return Result.failure(IllegalStateException("token response missing access token"))

        val identity = withContext(Dispatchers.IO) {
            val api = ServerApi(serverUrl)
            val device = EnrollDeviceInfo(
                hostname = Build.MODEL,
                os = "android",
                arch = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
                platform = "android",
                form_factor = if (activity.resources.configuration.smallestScreenWidthDp >= 600) "tablet" else "phone",
                management_mode = ManagementMode.resolve(activity),
            )
            val enrollResp = api.enrollWithOAuth(accessToken, device)
            val saved = AgentIdentity(
                agentId = enrollResp.agent_id,
                deviceId = enrollResp.device_id,
                authToken = enrollResp.auth_token,
                status = enrollResp.status,
                enrollmentMethod = "oauth",
                serverUrl = serverUrl,
                zitiIdentityJson = enrollResp.ziti_jwt,
                enrolledAtIso = enrollResp.enrolled_at.ifBlank { Instant.now().toString() },
            )
            IdentityStore(activity).save(saved)
            enrollResp.ziti_jwt?.takeIf { it.isNotBlank() }?.let { jwt ->
                ZitiClient(activity).enrollWithJwt(jwt, identityAlias = enrollResp.agent_id)
            }
            saved
        }
        return Result.success(identity)
    }

    fun dispose() = authService.dispose()

    companion object {
        const val REQUEST_CODE = 0xA101
        const val REDIRECT_URI = "com.openidx.agent://oauth/redirect"
        const val DEFAULT_CLIENT_ID = "openidx-agent-android"
    }
}
