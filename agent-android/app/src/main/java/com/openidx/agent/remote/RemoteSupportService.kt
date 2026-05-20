package com.openidx.agent.remote

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.openidx.agent.R
import com.openidx.agent.core.IdentityStore
import com.openidx.agent.enrollment.QrEnrollmentBootstrapper

/**
 * Foreground service that hosts a single remote-support session. Two roles:
 *
 *   1. Owns the persistent, non-suppressible "Remote support session active"
 *      notification — Android 12+ requires it for any foreground service of
 *      type mediaProjection, and we use it as the consent banner so the
 *      user always knows when an admin can see / control the device.
 *
 *   2. Owns the RemoteSupportEngine lifecycle so the WebRTC stack and
 *      MediaProjection are cleanly torn down when the user (or admin)
 *      ends the session.
 *
 * Started by RemoteSupportTriggerActivity once MediaProjection consent has
 * been granted; stopped by [stop] (admin end / user tap End).
 */
class RemoteSupportService : Service() {

    private var engine: RemoteSupportEngine? = null
    @Volatile private var recordingActive: Boolean = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureChannel()
        // Latch the recording flag BEFORE starting the foreground service
        // so buildBanner() — invoked synchronously below — reflects the
        // right text on first display.
        recordingActive = intent?.getBooleanExtra(EXTRA_RECORDING, false) == true
        startForeground(NOTIFICATION_ID, buildBanner())

        if (intent?.action == ACTION_END) {
            stop()
            return START_NOT_STICKY
        }

        val grant: Intent? = intent?.getParcelableExtra(EXTRA_MP_PERMISSION_RESULT)
        val sessionId = intent?.getStringExtra(EXTRA_SESSION_ID).orEmpty()
        val wsPath = intent?.getStringExtra(EXTRA_WS_PATH).orEmpty()
        val mode = intent?.getStringExtra(EXTRA_MODE) ?: "interactive"
        val ice = intent?.getStringExtra(EXTRA_ICE_SERVERS).orEmpty()

        if (grant == null || sessionId.isBlank() || wsPath.isBlank()) {
            stop()
            return START_NOT_STICKY
        }

        val identity = IdentityStore(this).load() ?: run {
            stop()
            return START_NOT_STICKY
        }

        val injector = InputInjector(this, QrEnrollmentBootstrapper.adminComponent)
        val newEngine = RemoteSupportEngine(
            context = this,
            identity = identity,
            sessionId = sessionId,
            wsPath = wsPath,
            mode = mode,
            iceServersJson = ice,
            injector = injector,
        )
        engine = newEngine
        newEngine.start(grant)
        return START_STICKY
    }

    override fun onDestroy() {
        engine?.stop()
        engine = null
        super.onDestroy()
    }

    private fun stop() {
        engine?.stop()
        engine = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "OpenIDX Remote Support",
                // Importance MAX so the banner can't be silenced — users
                // must visually see when an admin is connected.
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Shown while a remote-support session is live."
                setShowBadge(true)
                enableLights(true)
            }
        )
    }

    private fun buildBanner(): Notification {
        val endIntent = Intent(this, RemoteSupportService::class.java).apply { action = ACTION_END }
        val endPI = PendingIntent.getService(
            this, 1, endIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        // When recording is active, swap the banner text to the recording
        // variant so the device user reads "is recording" instead of the
        // softer "can see and control". Title stays neutral so the channel
        // remains a single channel users can manage in Settings.
        val titleRes = if (recordingActive)
            R.string.remote_support_recording_notification_title
        else
            R.string.remote_support_notification_title
        val textRes = if (recordingActive)
            R.string.remote_support_recording_notification_text
        else
            R.string.remote_support_notification_text
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentTitle(getString(titleRes))
            .setContentText(getString(textRes))
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .addAction(0, getString(R.string.remote_support_end_action), endPI)
            .setForegroundServiceBehavior(
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE
                else
                    NotificationCompat.FOREGROUND_SERVICE_DEFAULT
            )
            .build()
    }

    companion object {
        const val CHANNEL_ID = "openidx_remote_support"
        const val NOTIFICATION_ID = 1002
        const val ACTION_END = "com.openidx.agent.REMOTE_SUPPORT_END"

        const val EXTRA_MP_PERMISSION_RESULT = "mp_grant"
        const val EXTRA_SESSION_ID = "session_id"
        const val EXTRA_WS_PATH = "ws_path"
        const val EXTRA_MODE = "mode"
        const val EXTRA_ICE_SERVERS = "ice_servers"
        const val EXTRA_RECORDING = "recording"

        fun start(
            context: Context,
            mpGrant: Intent,
            sessionId: String,
            wsPath: String,
            mode: String,
            iceServers: String,
            recording: Boolean,
        ) {
            val intent = Intent(context, RemoteSupportService::class.java).apply {
                putExtra(EXTRA_MP_PERMISSION_RESULT, mpGrant)
                putExtra(EXTRA_SESSION_ID, sessionId)
                putExtra(EXTRA_WS_PATH, wsPath)
                putExtra(EXTRA_MODE, mode)
                putExtra(EXTRA_ICE_SERVERS, iceServers)
                putExtra(EXTRA_RECORDING, recording)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }
}
