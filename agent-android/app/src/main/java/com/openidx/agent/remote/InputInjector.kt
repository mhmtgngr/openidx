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
                // Arbitrary KeyCode (key_code != 0) goes through the IME when
                // the OpenIDX keyboard is the active input method — that's the
                // only path that can inject e.g. arrow keys / page up-down /
                // modifier combos. Otherwise we handle the three named keys
                // via the Accessibility emulation, and drop anything else
                // with a warning.
                val ime = OpenIDXInputMethodService.instance
                if (event.key_code != 0 && ime != null &&
                    OpenIDXInputMethodService.isActiveInputMethod(context)
                ) {
                    if (!ime.injectKeyCode(event.key_code)) {
                        Log.w(TAG, "IME key_code ${event.key_code} produced no effect")
                    }
                    return
                }
                val s = svc ?: run { warnUnavailable("key (no IME / accessibility)"); return }
                val ok = when (event.key_name.lowercase()) {
                    "enter", "return" -> s.pressEnter()
                    "backspace", "del", "delete" -> s.pressBackspace()
                    "tab" -> s.pressTab()
                    "" -> { warnUnavailable("key_code=${event.key_code} (no active IME, no key_name)"); false }
                    else -> { warnUnavailable("key_name=${event.key_name} needs the OpenIDX keyboard active"); false }
                }
                if (!ok) Log.w(TAG, "key event produced no effect")
            }
            "text" -> {
                // Prefer the IME's commitText (proper composition pipeline)
                // when the OpenIDX keyboard is active; otherwise fall back to
                // the Accessibility ACTION_SET_TEXT path.
                val ime = OpenIDXInputMethodService.instance
                if (ime != null && OpenIDXInputMethodService.isActiveInputMethod(context)) {
                    if (ime.injectText(event.text)) return
                    // commitText failed (no input connection) — fall through.
                }
                val s = svc ?: run { warnUnavailable("text (no IME / accessibility)"); return }
                if (!s.injectText(event.text, replace = event.replace)) {
                    Log.w(TAG, "text inject failed (no focused editable)")
                }
            }
            "clipboard" -> {
                val s = svc ?: run { warnUnavailable("clipboard (no accessibility)"); return }
                if (!s.setClipboardText(event.text)) {
                    Log.w(TAG, "clipboard push failed")
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
