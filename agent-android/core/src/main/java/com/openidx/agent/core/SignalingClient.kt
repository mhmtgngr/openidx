package com.openidx.agent.core

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

/**
 * Tiny WebSocket signaling client over the OpenIDX broker. Connect with
 * the agent's X-Agent-ID / X-Auth-Token credentials (validated server-side
 * against enrolled_agents.auth_token_hash).
 *
 * The client exposes incoming messages as a [SharedFlow] so multiple
 * downstream coroutines (WebRTC negotiator, input dispatcher, lifecycle
 * UI) can subscribe without fighting over a single channel.
 */
class SignalingClient(
    private val baseUrl: String,
    private val identity: AgentIdentity,
    httpClient: OkHttpClient = OkHttpClient(),
) {
    private val client: OkHttpClient = httpClient.newBuilder()
        // No read timeout — WebSocket needs to stay open even when no
        // signaling traffic flows (the underlying WebRTC track does its
        // own keepalive).
        .readTimeout(0, java.util.concurrent.TimeUnit.MILLISECONDS)
        .build()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val _incoming = MutableSharedFlow<SignalingEnvelope>(extraBufferCapacity = 16)
    val incoming: SharedFlow<SignalingEnvelope> = _incoming
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Volatile private var socket: WebSocket? = null
    @Volatile private var lifecycleJob: Job? = null

    // Marked @PublishedApi internal so the inline reified sendEnvelope below
    // can reach it after inlining at the call site. Not part of the public
    // API surface.
    @PublishedApi internal val outboundJson = json

    fun connect(wsPath: String) {
        disconnect()
        val url = baseUrl.replaceFirst(Regex("^http"), "ws")
            .trimEnd('/') + wsPath
        val req = Request.Builder()
            .url(url)
            .header("X-Agent-ID", identity.agentId)
            .header("X-Auth-Token", identity.authToken)
            .build()
        lifecycleJob = scope.launch {
            socket = client.newWebSocket(req, object : WebSocketListener() {
                override fun onOpen(ws: WebSocket, response: Response) {
                    Log.i(TAG, "signaling open ${response.code}")
                    // Tell the broker we're ready; the admin may have been
                    // waiting on the pending → active transition.
                    sendControl("accept")
                }

                override fun onMessage(ws: WebSocket, text: String) {
                    runCatching { json.decodeFromString<SignalingEnvelope>(text) }
                        .onSuccess { _incoming.tryEmit(it) }
                        .onFailure { e -> Log.w(TAG, "decode failed: $text", e) }
                }

                override fun onMessage(ws: WebSocket, bytes: ByteString) {
                    onMessage(ws, bytes.utf8())
                }

                override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                    Log.i(TAG, "signaling closing: $code $reason")
                    ws.close(1000, null)
                }

                override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                    Log.w(TAG, "signaling failure", t)
                }
            })
        }
    }

    fun disconnect() {
        lifecycleJob?.cancel()
        lifecycleJob = null
        socket?.close(1000, null)
        socket = null
    }

    inline fun <reified T> sendEnvelope(type: String, payload: T) {
        sendRaw(type, outboundJson.encodeToString(kotlinx.serialization.serializer<T>(), payload))
    }

    fun sendControl(action: String, reason: String = "") {
        sendEnvelope("control", SessionControlMessage(action = action, reason = reason))
    }

    fun sendRaw(type: String, payloadJson: String) {
        val msg = """{"type":"$type","payload":$payloadJson}"""
        socket?.send(msg)
    }

    fun shutdown() {
        disconnect()
        scope.cancel()
    }

    private companion object {
        const val TAG = "SignalingClient"
    }
}
