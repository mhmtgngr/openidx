package com.openidx.agent.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.openidx.agent.OpenIDXAgentApplication
import com.openidx.agent.R
import com.openidx.agent.core.IdentityStore
import com.openidx.agent.core.PostureScheduler
import com.openidx.agent.core.ServerApi
import com.openidx.agent.core.ZitiClient
import com.openidx.agent.ui.EnrollmentActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Foreground service that owns:
 *   - The Ziti tunnel lifecycle for the enrolled identity.
 *   - The 60-second heartbeat that touches /agent/config so the server can
 *     update last_seen_at without waiting for a posture cycle.
 *   - The persistent "OpenIDX agent active" notification required by
 *     Android 12+ for any background app that holds network resources.
 *
 * The slower posture-reporting cycle is delegated to WorkManager via
 * [PostureScheduler] so the system can batch it intelligently with other
 * periodic work and survive process death.
 */
class OpenIDXAgentService : Service() {

    private val supervisor = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + supervisor)
    private var heartbeatJob: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIFICATION_ID, buildNotification())

        val store = IdentityStore(this)
        val identity = store.load() ?: run {
            // Not enrolled — nothing to do, stop self.
            stopSelf()
            return
        }

        ZitiClient(this).initializeFromStored()

        // Schedule the periodic posture report. WorkManager runs the worker
        // even when this service is killed by the system.
        PostureScheduler(this).schedule(java.time.Duration.ofMinutes(15))

        heartbeatJob?.cancel()
        heartbeatJob = scope.launch {
            val api = ServerApi(identity.serverUrl)
            while (true) {
                runCatching { api.fetchConfig(identity) }
                delay(60_000)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onDestroy() {
        heartbeatJob?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    private fun buildNotification(): Notification {
        val tapIntent = Intent(this, EnrollmentActivity::class.java)
        val tapPI = PendingIntent.getActivity(
            this, 0, tapIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, OpenIDXAgentApplication.CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.agent_active_notification))
            .setContentIntent(tapPI)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setForegroundServiceBehavior(
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE
                else
                    NotificationCompat.FOREGROUND_SERVICE_DEFAULT
            )
            .build()
    }

    companion object {
        const val NOTIFICATION_ID = 1001

        fun start(context: Context) {
            val intent = Intent(context, OpenIDXAgentService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, OpenIDXAgentService::class.java))
        }
    }
}
