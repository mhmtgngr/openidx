package com.openidx.agent.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Wire types for the OpenIDX `/agent/*` HTTP API. Field names match the Go
 * structs in /internal/access/agent_api.go verbatim — keep them in sync when
 * the server protocol changes.
 */
@Serializable
data class EnrollDeviceInfo(
    val hostname: String = "",
    val os: String = "android",
    val arch: String = "",
    val platform: String = "android",
    val form_factor: String = "phone",
)

@Serializable
data class EnrollResponse(
    val agent_id: String,
    val device_id: String,
    val auth_token: String,
    val status: String,
    val enrollment_method: String = "",
    val enrolled_at: String = "",
    val ziti_jwt: String? = null,
)

@Serializable
data class PostureResultDetail(
    val status: String,
    val score: Double,
    val message: String = "",
    val details: Map<String, JsonElement> = emptyMap(),
)

@Serializable
data class PostureCheckResult(
    val check_type: String,
    val severity: String,
    val result: PostureResultDetail,
    val ran_at: String,
)

@Serializable
data class PostureReport(
    val agent_id: String,
    val device_id: String,
    val results: List<PostureCheckResult>,
)

@Serializable
data class AgentCheckConfig(
    val name: String,
    val enabled: Boolean = true,
    val check_type: String = "",
    val severity: String = "medium",
)

@Serializable
data class AgentConfigResponse(
    val checks: List<AgentCheckConfig> = emptyList(),
    val report_interval: String = "1h",
    val enforcement_policy: String = "monitor",
)

/**
 * Thin client over the public `/agent/*` endpoints on the access service. The
 * underlying [OkHttpClient] is swappable so the foreground service can plug
 * in a Ziti-tunneled client once enrollment finishes; before that, the
 * default direct-HTTPS client is used for enrollment-time bootstrapping.
 */
class ServerApi(
    private val baseUrl: String,
    private val httpClient: OkHttpClient = OkHttpClient(),
) {

    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    /** Token-based enrollment (QR / Device-Owner provisioning path). */
    suspend fun enrollWithToken(token: String, device: EnrollDeviceInfo): EnrollResponse =
        withContext(Dispatchers.IO) {
            val body = json.encodeToString(EnrollDeviceInfo.serializer(), device)
                .toRequestBody(jsonMediaType)
            val req = Request.Builder()
                .url("$baseUrl/api/v1/access/agent/enroll")
                .header("Authorization", "Bearer $token")
                .post(body)
                .build()
            httpClient.newCall(req).execute().use { resp ->
                check(resp.isSuccessful) { "enroll failed: ${resp.code} ${resp.message}" }
                json.decodeFromString(EnrollResponse.serializer(), resp.body!!.string())
            }
        }

    /** OAuth-based enrollment (email/login path). Sends a tenant JWT. */
    suspend fun enrollWithOAuth(accessToken: String, device: EnrollDeviceInfo): EnrollResponse =
        withContext(Dispatchers.IO) {
            val body = json.encodeToString(EnrollDeviceInfo.serializer(), device)
                .toRequestBody(jsonMediaType)
            val req = Request.Builder()
                .url("$baseUrl/api/v1/access/agent/enroll/oauth")
                .header("Authorization", "Bearer $accessToken")
                .post(body)
                .build()
            httpClient.newCall(req).execute().use { resp ->
                check(resp.isSuccessful) { "oauth enroll failed: ${resp.code} ${resp.message}" }
                json.decodeFromString(EnrollResponse.serializer(), resp.body!!.string())
            }
        }

    /** Submit a posture report. */
    suspend fun report(identity: AgentIdentity, report: PostureReport) =
        withContext(Dispatchers.IO) {
            val body = json.encodeToString(PostureReport.serializer(), report)
                .toRequestBody(jsonMediaType)
            val req = Request.Builder()
                .url("$baseUrl/api/v1/access/agent/report")
                .header("X-Agent-ID", identity.agentId)
                .header("X-Auth-Token", identity.authToken)
                .post(body)
                .build()
            httpClient.newCall(req).execute().use { resp ->
                check(resp.code == 202 || resp.isSuccessful) {
                    "report failed: ${resp.code} ${resp.message}"
                }
            }
        }

    /** Pull the current agent configuration (check list, intervals, policy). */
    suspend fun fetchConfig(identity: AgentIdentity): AgentConfigResponse =
        withContext(Dispatchers.IO) {
            val req = Request.Builder()
                .url("$baseUrl/api/v1/access/agent/config")
                .header("X-Agent-ID", identity.agentId)
                .header("X-Auth-Token", identity.authToken)
                .get()
                .build()
            httpClient.newCall(req).execute().use { resp ->
                check(resp.isSuccessful) { "config fetch failed: ${resp.code}" }
                json.decodeFromString(AgentConfigResponse.serializer(), resp.body!!.string())
            }
        }
}
