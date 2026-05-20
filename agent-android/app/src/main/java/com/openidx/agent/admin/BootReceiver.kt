package com.openidx.agent.admin

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.openidx.agent.core.IdentityStore
import com.openidx.agent.service.OpenIDXAgentService

/**
 * Re-starts the foreground agent service after boot so device reboots don't
 * silently disable posture reporting. We only start if an identity is
 * persisted; otherwise the device is enrolled in nothing and the service
 * has no work to do.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!IdentityStore(context).isEnrolled()) return
        OpenIDXAgentService.start(context)
    }
}
