package com.openidx.agent.core

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.time.Duration
import java.util.concurrent.TimeUnit

/**
 * Provides a parsed [Duration] for an OpenIDX-format interval string (e.g.
 * "15m", "1h", "24h", "30s") returned by /agent/config. Defaults to 1 hour
 * on parse failure so a malformed config can't disable reporting entirely.
 */
internal fun parseInterval(raw: String?): Duration {
    if (raw.isNullOrBlank()) return Duration.ofHours(1)
    val unit = raw.last()
    val numPart = raw.dropLast(1).toLongOrNull() ?: return Duration.ofHours(1)
    return when (unit) {
        's' -> Duration.ofSeconds(numPart)
        'm' -> Duration.ofMinutes(numPart)
        'h' -> Duration.ofHours(numPart)
        'd' -> Duration.ofDays(numPart)
        else -> Duration.ofHours(1)
    }
}

/**
 * Schedules periodic posture-reporting work via WorkManager. The actual work
 * is implemented by the app module's PostureWorker, which is referenced here
 * only by its fully-qualified class name so the core module stays free of
 * application-layer dependencies.
 *
 * WorkManager survives reboot, doze, and app process death, which is the
 * behavior we need to mirror the Go agent's "always reporting" contract.
 */
class PostureScheduler(private val context: Context) {

    /**
     * Schedule the report job with the given interval. WorkManager clamps
     * periodic intervals to a 15 minute minimum; finer-grained reporting
     * relies on the foreground service's own loop, not on WorkManager.
     */
    fun schedule(interval: Duration, workerClassName: String = POSTURE_WORKER_CLASS) {
        val effective = if (interval.toMinutes() < 15) Duration.ofMinutes(15) else interval

        val workerClass = runCatching {
            @Suppress("UNCHECKED_CAST")
            Class.forName(workerClassName) as Class<out androidx.work.ListenableWorker>
        }.getOrNull() ?: return // app module not yet present (tests)

        val request = PeriodicWorkRequestBuilder<androidx.work.ListenableWorker>(
            workerClass,
            effective.toMinutes(), TimeUnit.MINUTES,
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .addTag(WORK_TAG)
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            UNIQUE_WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            request,
        )
    }

    fun cancel() {
        WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_WORK_NAME)
    }

    companion object {
        const val UNIQUE_WORK_NAME = "openidx.posture.report"
        const val WORK_TAG = "openidx.posture"
        const val POSTURE_WORKER_CLASS = "com.openidx.agent.service.PostureWorker"
    }
}
