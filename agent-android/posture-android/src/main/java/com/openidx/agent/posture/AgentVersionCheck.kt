package com.openidx.agent.posture

import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonPrimitive

/**
 * Mirrors agent_version.go. Reports the running agent version so the server
 * can decide whether the device is on a supported release. Always passes —
 * the enforcement decision lives server-side where the minimum-version
 * policy is defined.
 */
class AgentVersionCheck(
    private val versionName: String,
    private val versionCode: Int,
) : PostureCheck {

    override val checkType: String = "agent_version"
    override val defaultSeverity: String = "low"

    override suspend fun run(): PostureCheck.CheckOutcome {
        return PostureCheck.CheckOutcome(
            status = PostureCheck.Status.PASS,
            score = 1.0,
            message = "OpenIDX agent $versionName ($versionCode)",
            details = mapOf(
                "version_name" to JsonPrimitive(versionName),
                "version_code" to JsonPrimitive(versionCode),
            ),
        )
    }
}
