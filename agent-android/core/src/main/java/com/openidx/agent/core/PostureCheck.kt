package com.openidx.agent.core

import kotlinx.serialization.json.JsonElement

/**
 * Common interface implemented by every posture check the agent ships. Each
 * check produces a [PostureCheckResult] that the foreground service batches
 * into a single /agent/report submission. Checks must not throw — they
 * convert failures into a status="error" result so one broken check doesn't
 * silence the entire posture cycle.
 */
interface PostureCheck {
    /** Stable identifier matching `check_type` in posture_checks. */
    val checkType: String

    /** Default severity if the server config doesn't override. */
    val defaultSeverity: String

    /** Run the check. Implementations may suspend (network, IO, IPC). */
    suspend fun run(): CheckOutcome

    /** Outcome of a single check evaluation, pre-server-side enforcement. */
    data class CheckOutcome(
        val status: Status,
        val score: Double,
        val message: String = "",
        val details: Map<String, JsonElement> = emptyMap(),
    )

    enum class Status(val wire: String) {
        PASS("pass"),
        FAIL("fail"),
        WARN("warn"),
        ERROR("error"),
    }
}
