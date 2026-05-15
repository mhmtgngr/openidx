package com.openidx.agent.posture

import android.os.Build
import com.openidx.agent.core.PostureCheck
import kotlinx.serialization.json.JsonPrimitive
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

/**
 * Mirrors patch_level.go on Android. Build.VERSION.SECURITY_PATCH is the
 * OEM-reported date of the most recent security patch level. The check fails
 * when the device hasn't received a patch in [maxStaleDays] days — server
 * config typically supplies that threshold (90d default).
 */
class PatchLevelCheck(
    private val maxStaleDays: Long = 90,
    private val today: LocalDate = LocalDate.now(),
) : PostureCheck {

    override val checkType: String = "patch_level"
    override val defaultSeverity: String = "high"

    override suspend fun run(): PostureCheck.CheckOutcome {
        val raw = Build.VERSION.SECURITY_PATCH
        if (raw.isNullOrBlank()) {
            return PostureCheck.CheckOutcome(
                status = PostureCheck.Status.ERROR,
                score = 0.0,
                message = "Security patch date not reported by OEM",
            )
        }
        val patchDate = runCatching {
            LocalDate.parse(raw, DateTimeFormatter.ofPattern("yyyy-MM-dd"))
        }.getOrNull()
        if (patchDate == null) {
            return PostureCheck.CheckOutcome(
                status = PostureCheck.Status.ERROR,
                score = 0.0,
                message = "Security patch field unparseable: $raw",
                details = mapOf("raw" to JsonPrimitive(raw)),
            )
        }
        val ageDays = ChronoUnit.DAYS.between(patchDate, today)
        val pass = ageDays in 0..maxStaleDays
        return PostureCheck.CheckOutcome(
            status = if (pass) PostureCheck.Status.PASS else PostureCheck.Status.FAIL,
            score = if (pass) 1.0 else 0.0,
            message = "Patch $raw (${ageDays}d old)",
            details = mapOf(
                "security_patch" to JsonPrimitive(raw),
                "age_days" to JsonPrimitive(ageDays),
                "max_stale_days" to JsonPrimitive(maxStaleDays),
            ),
        )
    }
}
