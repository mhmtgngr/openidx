package com.openidx.agent.posture

import android.content.ComponentName
import android.content.Context
import com.openidx.agent.core.AgentCheckConfig
import com.openidx.agent.core.PostureCheck
import com.openidx.agent.core.PostureCheckResult
import com.openidx.agent.core.PostureResultDetail
import java.time.Instant

/**
 * Resolves the server-supplied [AgentCheckConfig] list to concrete check
 * implementations and executes them. Returns the wire-shaped
 * [PostureCheckResult] list ready for /agent/report.
 *
 * Built-in checks are keyed by their `checkType`. Unknown check types are
 * dropped silently — the server-side config can include checks that don't
 * yet have an Android implementation, and that's not a fatal condition for
 * the agent (just nothing to report for those checks).
 */
class PostureRunner(
    private val context: Context,
    private val adminComponent: ComponentName,
    private val versionName: String,
    private val versionCode: Int,
) {

    private fun builtinChecks(): Map<String, PostureCheck> = mapOf(
        "os_version"           to OsVersionCheck(),
        "disk_encryption"      to DiskEncryptionCheck(context),
        "screen_lock"          to ScreenLockCheck(context),
        "patch_level"          to PatchLevelCheck(),
        "play_integrity"       to IntegrityCheck(context),
        "enterprise_managed"   to EnterpriseManagedCheck(context, adminComponent),
        "developer_options"    to DeveloperOptionsCheck(context),
        "unknown_sources"      to UnknownSourcesCheck(context),
        "accessibility_audit"  to AccessibilityAuditCheck(context),
        "agent_version"        to AgentVersionCheck(versionName, versionCode),
    )

    suspend fun runAll(configs: List<AgentCheckConfig>): List<PostureCheckResult> {
        val checks = builtinChecks()
        val now = Instant.now().toString()
        return configs.mapNotNull { cfg ->
            val key = cfg.check_type.ifBlank { cfg.name }
            val check = checks[key] ?: return@mapNotNull null
            val outcome = runCatching { check.run() }.getOrElse { e ->
                PostureCheck.CheckOutcome(
                    status = PostureCheck.Status.ERROR,
                    score = 0.0,
                    message = "check threw: ${e.message ?: e.javaClass.simpleName}",
                )
            }
            PostureCheckResult(
                check_type = check.checkType,
                severity = cfg.severity.ifBlank { check.defaultSeverity },
                result = PostureResultDetail(
                    status = outcome.status.wire,
                    score = outcome.score,
                    message = outcome.message,
                    details = outcome.details,
                ),
                ran_at = now,
            )
        }
    }
}
