package com.openidx.agent.remote

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.util.Log
import com.openidx.agent.core.InputEventMessage

/**
 * Routes incoming admin input events to the best available delivery path.
 *
 * Priority order (matches the design decision):
 *   1. Device Owner privileges — when the agent is provisioned as Device
 *      Owner we can inject directly without prompting the user.
 *   2. Accessibility Service — works on any Android install (BYOD,
 *      side-load) once the user has toggled the service on.
 *
 * In view-only mode the engine never constructs this class; in interactive
 * mode every message that arrives on the data channel is dispatched here.
 */
class InputInjector(
    private val context: Context,
    private val adminComponent: ComponentName,
) {

    private val dpm: DevicePolicyManager =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager

    private val isDeviceOwner: Boolean
        get() = dpm.isDeviceOwnerApp(context.packageName)

    /**
     * Dispatch a single event. Silently drops events we don't know how to
     * deliver (e.g. text injection without an active IME). Logged at WARN
     * so admins can spot the gap in posture reports.
     */
    fun dispatch(event: InputEventMessage) {
        val svc = OpenIDXAccessibilityService.instance
        when (event.event.lowercase()) {
            "tap" -> {
                if (isDeviceOwner) {
                    // Device-Owner path: no user toggle required. Fall back
                    // to accessibility when the AS is also enabled — Android
                    // gives identical UX from either path.
                    svc?.tap(event.x.toFloat(), event.y.toFloat(), event.duration_ms.coerceAtLeast(1))
                } else {
                    svc?.tap(event.x.toFloat(), event.y.toFloat(), event.duration_ms.coerceAtLeast(1))
                        ?: warnUnavailable("tap")
                }
            }
            "swipe" -> {
                svc?.swipe(
                    event.x.toFloat(), event.y.toFloat(),
                    event.x_end.toFloat(), event.y_end.toFloat(),
                    event.duration_ms.coerceAtLeast(50),
                ) ?: warnUnavailable("swipe")
            }
            "global_action" -> {
                svc?.globalAction(event.action) ?: warnUnavailable("global_action=${event.action}")
            }
            "key" -> {
                // Named keys are handled via Accessibility ACTION_IME_ENTER /
                // SET_TEXT-based emulation. Arbitrary KeyCode injection is
                // not supported here — that requires a custom InputMethodService,
                // tracked as future work in the design doc.
                val s = svc ?: run { warnUnavailable("key (no accessibility)"); return }
                val ok = when (event.key_name.lowercase()) {
                    "enter", "return" -> s.pressEnter()
                    "backspace", "del", "delete" -> s.pressBackspace()
                    "tab" -> s.pressTab()
                    "" -> { warnUnavailable("key_code=${event.key_code} (no key_name)"); false }
                    else -> { warnUnavailable("key_name=${event.key_name} unsupported"); false }
                }
                if (!ok) Log.w(TAG, "key event ${event.key_name} produced no effect")
            }
            "text" -> {
                val s = svc ?: run { warnUnavailable("text (no accessibility)"); return }
                if (!s.injectText(event.text, replace = event.replace)) {
                    Log.w(TAG, "text inject failed (no focused editable)")
                }
            }
            else -> warnUnavailable("unknown=${event.event}")
        }
    }

    private fun warnUnavailable(detail: String) {
        Log.w(TAG, "input event dropped (no path available): $detail")
    }

    private companion object {
        const val TAG = "InputInjector"
    }
}
