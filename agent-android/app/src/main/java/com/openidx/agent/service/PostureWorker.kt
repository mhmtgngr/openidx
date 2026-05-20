package com.openidx.agent.service

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.openidx.agent.BuildConfig
import com.openidx.agent.core.IdentityStore
import com.openidx.agent.core.PostureReport
import com.openidx.agent.core.ServerApi
import com.openidx.agent.enrollment.QrEnrollmentBootstrapper
import com.openidx.agent.posture.PostureRunner

/**
 * WorkManager worker that runs one posture cycle: pull the active config
 * from /agent/config, execute the agent-side checks via [PostureRunner],
 * and POST the results to /agent/report.
 *
 * Returns Result.success() even on per-call failures so WorkManager keeps
 * the periodic schedule alive; transient errors are surfaced via the system
 * logger for diagnostics rather than retry storms.
 */
class PostureWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val store = IdentityStore(applicationContext)
        val identity = store.load() ?: return Result.success()

        val api = ServerApi(identity.serverUrl)
        val config = runCatching { api.fetchConfig(identity) }.getOrNull()
            ?: return Result.success().also { Log.w(TAG, "config fetch failed") }

        val runner = PostureRunner(
            context = applicationContext,
            adminComponent = QrEnrollmentBootstrapper.adminComponent,
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
        )
        val results = runner.runAll(config.checks)
        if (results.isEmpty()) return Result.success()

        runCatching {
            api.report(
                identity,
                PostureReport(
                    agent_id = identity.agentId,
                    device_id = identity.deviceId,
                    results = results,
                )
            )
        }.onFailure { e -> Log.w(TAG, "report failed", e) }

        return Result.success()
    }

    private companion object {
        const val TAG = "PostureWorker"
    }
}
