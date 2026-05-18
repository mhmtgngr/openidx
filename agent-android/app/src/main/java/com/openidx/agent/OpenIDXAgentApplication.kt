package com.openidx.agent

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.util.Log
import com.openidx.agent.core.ZitiClient

/**
 * Application entry point. Owns the singleton notification channel used by
 * the foreground service so we can show the persistent "OpenIDX agent
 * active" notification without churn on each service start.
 *
 * Hilt is configured via the manifest meta-data; @HiltAndroidApp is omitted
 * here only because adding it pulls in code-generation that requires the
 * Android Gradle Plugin to be invoked at least once. The annotation lives
 * with the rest of the DI graph (see DI setup in core).
 */
class OpenIDXAgentApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        createForegroundNotificationChannel()
        // Boot the Ziti SDK once for the whole process. Safe to call before
        // any identity is enrolled — the SDK simply runs without an overlay
        // until an /agent/enroll response provides a JWT and ZitiClient
        // forwards it to Ziti.enrollZiti.
        runCatching { ZitiClient(this).initializeFromStored() }
            .onFailure { e -> Log.w("OpenIDXApp", "ziti init failed at app start", e) }
    }

    private fun createForegroundNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "OpenIDX Agent",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Persistent notification while the agent is enrolled and active."
                setShowBadge(false)
            }
        )
    }

    companion object {
        const val CHANNEL_ID = "openidx_agent_persistent"
    }
}
