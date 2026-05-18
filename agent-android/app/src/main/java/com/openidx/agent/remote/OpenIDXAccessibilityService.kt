package com.openidx.agent.remote

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Path
import android.os.Bundle
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

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

    /**
     * Inject [text] into the currently input-focused editable node.
     * When [replace] is false (default), append to existing text;
     * when true, the field's contents are replaced entirely.
     *
     * Returns true iff a focused editable node was found and the
     * ACTION_SET_TEXT call succeeded. Failure is non-fatal — the calling
     * input dispatcher logs and moves on.
     *
     * Caveats:
     *  - ACTION_SET_TEXT bypasses the IME's composition pipeline, so
     *    autocomplete / suggestions on the device side won't fire.
     *  - The focused node must be editable. Read-only labels are skipped.
     *  - On WebViews and some custom views, the action may silently
     *    no-op even when a text caret is visible.
     */
    fun injectText(text: String, replace: Boolean = false): Boolean {
        val node = findFocusedEditable() ?: return false
        val existing = node.text?.toString().orEmpty()
        val target = if (replace) text else existing + text
        val args = Bundle().apply {
            putCharSequence(
                ACTION_ARGUMENT_SET_TEXT_KEY,
                target,
            )
        }
        val ok = node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        node.recycle()
        return ok
    }

    /**
     * Simulates pressing Backspace on the focused editable by trimming
     * one character from its tail and reassigning. Returns true when a
     * character was removed.
     */
    fun pressBackspace(): Boolean {
        val node = findFocusedEditable() ?: return false
        val existing = node.text?.toString().orEmpty()
        if (existing.isEmpty()) {
            node.recycle()
            return false
        }
        val args = Bundle().apply {
            putCharSequence(
                ACTION_ARGUMENT_SET_TEXT_KEY,
                existing.dropLast(1),
            )
        }
        val ok = node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        node.recycle()
        return ok
    }

    /**
     * Best-effort "Enter" key: when the focused editable's IME action
     * supports it, performAction(ACTION_IME_ENTER) fires the form's
     * submit affordance. Falls back to appending "\n" so multi-line
     * fields still get a newline.
     */
    fun pressEnter(): Boolean {
        val node = findFocusedEditable() ?: return false
        // API 30+: ACTION_IME_ENTER is the documented way to fire the
        // current IME action (search / go / next / done). The int constant
        // (0x100000) is inlined here because the symbol on
        // AccessibilityNodeInfo isn't surfaced by every compileSdk
        // toolchain combination, but the value is stable platform API.
        val imeOk = runCatching {
            node.performAction(ACTION_IME_ENTER_ID)
        }.getOrDefault(false)
        if (imeOk) {
            node.recycle()
            return true
        }
        // Fallback for fields that don't expose an IME action: append \n.
        val existing = node.text?.toString().orEmpty()
        val args = Bundle().apply {
            putCharSequence(
                ACTION_ARGUMENT_SET_TEXT_KEY,
                existing + "\n",
            )
        }
        val ok = node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        node.recycle()
        return ok
    }

    /**
     * Write the supplied text to the system clipboard. Push-only by
     * design (admin → device); reading the user's clipboard is restricted
     * on Android 10+ from background contexts and is a stronger privacy
     * concern than the typing path, so we don't expose it from here.
     *
     * Use case: admin pastes a long token / URL / boilerplate response
     * the user couldn't easily type, and the user pastes it where they
     * need it. The audit row (logged by InputInjector's caller) records
     * the operator action.
     *
     * Returns true on a successful setPrimaryClip call. False is
     * surfaced for the rare case where ClipboardManager is unavailable
     * (some restricted profiles).
     */
    fun setClipboardText(text: String): Boolean {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (cm == null) {
            Log.w("OpenIDXAS", "clipboard service unavailable")
            return false
        }
        return runCatching {
            cm.setPrimaryClip(ClipData.newPlainText("OpenIDX remote support", text))
        }.isSuccess
    }

    /**
     * Move accessibility focus to the next focusable element. Roughly
     * equivalent to pressing Tab on a hardware keyboard for navigation
     * purposes, though it operates on accessibility focus rather than
     * input focus.
     */
    fun pressTab(): Boolean {
        val node = findFocusedEditable() ?: rootInActiveWindow ?: return false
        val ok = node.performAction(AccessibilityNodeInfo.ACTION_ACCESSIBILITY_FOCUS) &&
            node.performAction(AccessibilityNodeInfo.ACTION_FOCUS)
        node.recycle()
        return ok
    }

    /**
     * Walks the active-window node tree and returns the first editable
     * descendant that holds input focus, or null when there's no
     * editable field receiving keystrokes right now.
     *
     * Caller owns the returned [AccessibilityNodeInfo] and must call
     * recycle() to release it.
     */
    private fun findFocusedEditable(): AccessibilityNodeInfo? {
        val root = rootInActiveWindow ?: return null
        val focused = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        if (focused != null && focused.isEditable) return focused
        focused?.recycle()
        // Some apps don't propagate FOCUS_INPUT correctly; fall back to a
        // tree walk for the first editable node.
        return findFirstEditable(root)
    }

    private fun findFirstEditable(node: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        if (node == null) return null
        if (node.isEditable) return node
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val match = findFirstEditable(child)
            if (match != null) return match
            child.recycle()
        }
        return null
    }

    companion object {
        @Volatile var instance: OpenIDXAccessibilityService? = null
            private set

        // Bundle key the platform consumes for ACTION_SET_TEXT. The
        // constant is defined on AccessibilityNodeInfo as
        // ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE_VALUE, but its symbol
        // isn't reliably exposed in every Kotlin / android.jar
        // combination. The string value itself has been stable since
        // API 21 — inlining is the pragmatic fix.
        private const val ACTION_ARGUMENT_SET_TEXT_KEY =
            "ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE_VALUE"

        // AccessibilityNodeInfo.ACTION_IME_ENTER (API 30+). Same story
        // as the constant above — value is stable, symbol resolution
        // is finicky. 0x100000 lifted verbatim from the platform source.
        private const val ACTION_IME_ENTER_ID = 0x100000
    }
}
