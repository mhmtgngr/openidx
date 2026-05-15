package com.openidx.agent.remote

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.view.accessibility.AccessibilityEvent

/**
 * Accessibility Service used for the input-injection fallback path. On
 * Device-Owner devices we prefer the direct injection route, but on BYOD
 * installs (or wherever Device Owner provisioning never happened) this is
 * the only API that can drive taps, swipes, key presses, and global
 * actions on the user's behalf.
 *
 * The service is intentionally inert outside of an active remote-support
 * session — it does not consume accessibility events. We register an
 * empty event filter on the service config so we don't get screen-content
 * notifications when no admin is connected.
 */
class OpenIDXAccessibilityService : AccessibilityService() {

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Intentionally empty — we use the service only for outbound
        // injection via dispatchGesture / performGlobalAction.
    }

    override fun onInterrupt() {}

    fun tap(x: Float, y: Float, durationMs: Long = 100) {
        val path = Path().apply { moveTo(x, y); lineTo(x, y) }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs)
        dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), null, null)
    }

    fun swipe(x1: Float, y1: Float, x2: Float, y2: Float, durationMs: Long = 200) {
        val path = Path().apply { moveTo(x1, y1); lineTo(x2, y2) }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs)
        dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), null, null)
    }

    fun globalAction(action: String) {
        val code = when (action.lowercase()) {
            "back" -> GLOBAL_ACTION_BACK
            "home" -> GLOBAL_ACTION_HOME
            "recents" -> GLOBAL_ACTION_RECENTS
            "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
            "quick_settings" -> GLOBAL_ACTION_QUICK_SETTINGS
            else -> return
        }
        performGlobalAction(code)
    }

    companion object {
        @Volatile var instance: OpenIDXAccessibilityService? = null
            private set
    }
}
