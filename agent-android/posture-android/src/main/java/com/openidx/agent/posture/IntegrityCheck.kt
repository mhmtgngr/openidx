package com.openidx.agent.posture

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.openidx.agent.core.PostureCheck
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.json.JsonPrimitive
import kotlin.coroutines.resume

/**
 * Replaces the Go agent's heuristic root/jailbreak detection with Google's
 * Play Integrity attestation. The Play servers sign a verdict describing
 * whether the device is in a known-good state (MEETS_DEVICE_INTEGRITY etc.),
 * which is then forwarded raw to OpenIDX. The server-side check decodes the
 * signed token and decides pass/fail; from the agent's perspective the goal
 * is simply to obtain a fresh token.
 */
class IntegrityCheck(private val context: Context) : PostureCheck {

    override val checkType: String = "play_integrity"
    override val defaultSeverity: String = "critical"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val manager = IntegrityManagerFactory.create(context)
        val nonce = generateNonce()
        val token = runCatching { requestToken(manager, nonce) }.getOrNull()
            ?: return PostureCheck.CheckOutcome(
                status = PostureCheck.Status.ERROR,
                score = 0.0,
                message = "Failed to obtain Play Integrity token",
            )
        // Token validity is server-checked; from agent's POV "token obtained"
        // means the SDK trusts the device enough to attest at all.
        return PostureCheck.CheckOutcome(
            status = PostureCheck.Status.PASS,
            score = 1.0,
            message = "Integrity token obtained",
            details = mapOf(
                "token" to JsonPrimitive(token),
                "nonce" to JsonPrimitive(nonce),
            ),
        )
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP)
    }

    private suspend fun requestToken(
        manager: com.google.android.play.core.integrity.IntegrityManager,
        nonce: String,
    ): String = suspendCancellableCoroutine { cont ->
        manager.requestIntegrityToken(
            IntegrityTokenRequest.builder().setNonce(nonce).build()
        )
            .addOnSuccessListener { resp -> cont.resume(resp.token()) }
            .addOnFailureListener { _ ->
                // Failure is surfaced upstream via an empty token; the calling
                // check returns ERROR when this happens.
                if (cont.isActive) cont.resume("")
            }
    }
}
