package com.openidx.agent.remote

import android.content.Context
import android.inputmethodservice.InputMethodService
import android.provider.Settings
import android.util.Log
import android.view.KeyEvent
import android.view.View

/**
 * Headless input method whose only purpose is remote key / text
 * injection. Unlike the Accessibility path (which can only set text on a
 * focused node and fire a few named keys), an IME holds an
 * InputConnection to the focused field and can inject arbitrary
 * KeyEvents — arrow keys, escape, page up/down, modifier combos, the
 * full hardware-keyboard equivalent.
 *
 * The fundamental constraint: an IME can only inject into a field while
 * it is the *selected* input method for that field. So this service is
 * only usable for key injection when the user (or DPM, on Device-Owner
 * devices) has selected the OpenIDX keyboard. When it's not active,
 * InputInjector falls back to the Accessibility path.
 *
 * The keyboard view is intentionally empty — we never want to take over
 * the user's typing surface visually; we only borrow the IME plumbing
 * for the remote-control data path.
 */
class OpenIDXInputMethodService : InputMethodService() {

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onCreateInputView(): View {
        // Zero-height placeholder. We don't render a keyboard — the
        // service exists purely to relay injected events to the
        // InputConnection.
        return View(this)
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        super.onDestroy()
    }

    /**
     * Inject one key press (down + up) into the focused field via the
     * current InputConnection. metaState carries modifier flags
     * (KeyEvent.META_SHIFT_ON etc.); pass 0 for an unmodified press.
     * Returns true when the InputConnection accepted both events.
     */
    fun injectKeyCode(keyCode: Int, metaState: Int = 0): Boolean {
        val ic = currentInputConnection ?: return false
        val now = System.currentTimeMillis()
        val down = KeyEvent(now, now, KeyEvent.ACTION_DOWN, keyCode, 0, metaState)
        val up = KeyEvent(now, now, KeyEvent.ACTION_UP, keyCode, 0, metaState)
        val a = ic.sendKeyEvent(down)
        val b = ic.sendKeyEvent(up)
        return a && b
    }

    /**
     * Commit text into the focused field through the InputConnection.
     * Unlike the Accessibility ACTION_SET_TEXT path this goes through the
     * normal composition pipeline, so the target app sees it the same as
     * user typing. Returns true on success.
     */
    fun injectText(text: String): Boolean {
        val ic = currentInputConnection ?: return false
        return ic.commitText(text, 1)
    }

    companion object {
        @Volatile var instance: OpenIDXInputMethodService? = null
            private set

        /**
         * True when the OpenIDX IME is the device's currently-selected
         * input method, i.e. injection will actually reach a focused
         * field. Reads Settings.Secure.DEFAULT_INPUT_METHOD, which holds
         * the active IME's flattened component id.
         */
        fun isActiveInputMethod(context: Context): Boolean {
            val current = runCatching {
                Settings.Secure.getString(
                    context.contentResolver,
                    Settings.Secure.DEFAULT_INPUT_METHOD,
                )
            }.getOrNull().orEmpty()
            val match = current.startsWith(context.packageName + "/")
            if (!match && instance == null) {
                Log.d(TAG, "OpenIDX IME not active (current=$current)")
            }
            return match && instance != null
        }

        private const val TAG = "OpenIDXIME"
    }
}
