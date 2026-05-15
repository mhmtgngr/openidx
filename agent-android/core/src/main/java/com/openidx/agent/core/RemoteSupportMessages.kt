package com.openidx.agent.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Wire shapes for the remote-support signaling protocol. Messages are
 * relayed verbatim by the server broker between admin and agent, so both
 * peers agree on this schema.
 *
 * Every message has a `type` discriminator. Unknown types are ignored
 * (forward compatibility) so the server can add new envelope kinds — e.g.
 * a future "recording_started" event — without breaking either client.
 */

/** Top-level envelope. Use the type-specific decoders below. */
@Serializable
data class SignalingEnvelope(
    val type: String,
    val payload: JsonElement? = null,
)

@Serializable
data class SdpMessage(
    val sdp: String,
    val type: String, // "offer" | "answer"
)

@Serializable
data class IceCandidateMessage(
    val candidate: String,
    val sdp_mid: String? = null,
    val sdp_m_line_index: Int? = null,
)

@Serializable
data class InputEventMessage(
    val event: String,            // "tap" | "swipe" | "key" | "text" | "global_action"
    val x: Double = 0.0,
    val y: Double = 0.0,
    val x_end: Double = 0.0,
    val y_end: Double = 0.0,
    val duration_ms: Long = 0,
    val key_code: Int = 0,
    val text: String = "",
    val action: String = "",      // "back" | "home" | "recents" | "notifications"
)

@Serializable
data class SessionControlMessage(
    /** "accept" (agent acknowledges) | "decline" | "end" | "ping" */
    val action: String,
    val reason: String = "",
)
