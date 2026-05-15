package com.openidx.agent.remote

import android.app.Activity
import android.content.Intent
import android.media.projection.MediaProjectionManager
import android.os.Bundle

/**
 * Transparent helper activity whose only job is to request MediaProjection
 * consent. MediaProjectionManager.createScreenCaptureIntent() must be
 * launched from an activity — the foreground service can't request it on
 * its own — so the agent's main service launches this activity, this
 * activity prompts the user, and on success we hand the permission result
 * back to [RemoteSupportService] which spins up the WebRTC engine.
 *
 * Visually invisible: no setContentView call, theme transparent (set in
 * AndroidManifest). Lifecycle is fire-and-forget: started by the agent
 * heartbeat when /agent/config reports a pending session, finishes the
 * moment the consent dialog resolves.
 */
class RemoteSupportTriggerActivity : Activity() {

    private lateinit var sessionId: String
    private lateinit var wsPath: String
    private lateinit var mode: String
    private lateinit var iceServers: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sessionId = intent.getStringExtra(EXTRA_SESSION_ID).orEmpty()
        wsPath = intent.getStringExtra(EXTRA_WS_PATH).orEmpty()
        mode = intent.getStringExtra(EXTRA_MODE) ?: "interactive"
        iceServers = intent.getStringExtra(EXTRA_ICE_SERVERS).orEmpty()

        if (sessionId.isBlank() || wsPath.isBlank()) {
            finish()
            return
        }
        val mpm = getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        startActivityForResult(mpm.createScreenCaptureIntent(), REQ_MP)
    }

    @Deprecated("Activity Result API supersedes this, but it's adequate for a one-shot dialog")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_MP) {
            finish()
            return
        }
        if (resultCode == RESULT_OK && data != null) {
            RemoteSupportService.start(this, data, sessionId, wsPath, mode, iceServers)
        }
        // Either way (decline or success) we close the helper activity.
        finish()
    }

    companion object {
        const val REQ_MP = 0xC101
        const val EXTRA_SESSION_ID = "session_id"
        const val EXTRA_WS_PATH = "ws_path"
        const val EXTRA_MODE = "mode"
        const val EXTRA_ICE_SERVERS = "ice_servers"
    }
}
