package com.openidx.agent.remote

import android.content.Context
import android.content.Intent
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.util.Log
import com.openidx.agent.core.AgentIdentity
import com.openidx.agent.core.IceCandidateMessage
import com.openidx.agent.core.InputEventMessage
import com.openidx.agent.core.SdpMessage
import com.openidx.agent.core.SignalingClient
import com.openidx.agent.core.SignalingEnvelope
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.webrtc.DataChannel
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.ScreenCapturerAndroid
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import org.webrtc.SurfaceTextureHelper
import org.webrtc.VideoSource
import org.webrtc.VideoTrack
import java.nio.charset.StandardCharsets

/**
 * Glue that owns the WebRTC PeerConnection for one remote-support session.
 * Wiring:
 *
 *   signaling  ─▶ onIncoming  ─▶ setRemoteDescription / addIceCandidate
 *   capturer   ─▶ VideoSource ─▶ VideoTrack ─▶ PeerConnection
 *   data ch.   ─▶ InputInjector
 *
 * Lifecycle: callers construct one engine per session, call [start] with a
 * MediaProjection permission grant, and [stop] when the session ends. The
 * engine is not reusable — build a new one for the next session.
 */
class RemoteSupportEngine(
    private val context: Context,
    private val identity: AgentIdentity,
    private val sessionId: String,
    private val wsPath: String,
    private val mode: String,
    private val iceServersJson: String,
    private val injector: InputInjector,
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val signaling = SignalingClient(identity.serverUrl, identity)

    private val eglBase: EglBase by lazy { EglBase.create() }
    private val factory: PeerConnectionFactory by lazy { buildPeerFactory() }
    private var peerConnection: PeerConnection? = null
    private var capturer: ScreenCapturerAndroid? = null
    private var videoSource: VideoSource? = null
    private var videoTrack: VideoTrack? = null
    private var inputChannel: DataChannel? = null

    fun start(mediaProjectionPermissionResult: Intent) {
        // 1. PeerConnectionFactory must be initialized exactly once per process.
        ensureFactoryInitialized()

        // 2. PeerConnection with ICE servers from the session config.
        peerConnection = factory.createPeerConnection(
            buildRtcConfig(),
            object : SimplePeerObserver() {
                override fun onIceCandidate(candidate: IceCandidate) {
                    signaling.sendEnvelope(
                        "ice",
                        IceCandidateMessage(
                            candidate = candidate.sdp,
                            sdp_mid = candidate.sdpMid,
                            sdp_m_line_index = candidate.sdpMLineIndex,
                        )
                    )
                }
                override fun onDataChannel(dc: DataChannel) {
                    attachInputChannel(dc)
                }
            }
        )

        // 3. Screen capturer feeding the video track.
        capturer = ScreenCapturerAndroid(
            mediaProjectionPermissionResult,
            object : MediaProjection.Callback() {
                override fun onStop() {
                    Log.i(TAG, "media projection stopped by user")
                    stop()
                }
            }
        )
        val helper = SurfaceTextureHelper.create("openidx-cap", eglBase.eglBaseContext)
        videoSource = factory.createVideoSource(/* isScreencast = */ true)
        capturer!!.initialize(helper, context, videoSource!!.capturerObserver)
        capturer!!.startCapture(SCREEN_WIDTH, SCREEN_HEIGHT, SCREEN_FPS)
        videoTrack = factory.createVideoTrack("openidx-screen", videoSource!!).apply {
            setEnabled(true)
        }
        peerConnection!!.addTrack(videoTrack!!, listOf("openidx-stream"))

        // 4. Data channel for input injection in interactive mode. View-only
        //    sessions skip this — the agent ignores any incoming input.
        if (mode == "interactive") {
            val init = DataChannel.Init().apply { ordered = true }
            attachInputChannel(peerConnection!!.createDataChannel("openidx-input", init))
        }

        // 5. Subscribe to incoming signaling messages and dial the broker.
        scope.launch { signaling.incoming.collect(::onIncoming) }
        signaling.connect(wsPath)

        // 6. Tell the broker we're ready and create the SDP offer.
        createAndSendOffer()
    }

    fun stop() {
        runCatching { signaling.sendControl("end", "agent_ended") }
        signaling.shutdown()
        runCatching { capturer?.stopCapture() }
        capturer?.dispose(); capturer = null
        videoTrack?.dispose(); videoTrack = null
        videoSource?.dispose(); videoSource = null
        inputChannel?.close(); inputChannel = null
        peerConnection?.close(); peerConnection = null
        scope.cancel()
    }

    private fun ensureFactoryInitialized() {
        PeerConnectionFactory.initialize(
            PeerConnectionFactory.InitializationOptions
                .builder(context)
                .setEnableInternalTracer(false)
                .createInitializationOptions()
        )
    }

    private fun buildPeerFactory(): PeerConnectionFactory {
        val encoder = DefaultVideoEncoderFactory(eglBase.eglBaseContext, true, true)
        val decoder = DefaultVideoDecoderFactory(eglBase.eglBaseContext)
        return PeerConnectionFactory.builder()
            .setVideoEncoderFactory(encoder)
            .setVideoDecoderFactory(decoder)
            .createPeerConnectionFactory()
    }

    private fun buildRtcConfig(): PeerConnection.RTCConfiguration {
        val servers = parseIceServers(iceServersJson)
        val cfg = PeerConnection.RTCConfiguration(servers).apply {
            sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
            bundlePolicy = PeerConnection.BundlePolicy.MAXBUNDLE
            rtcpMuxPolicy = PeerConnection.RtcpMuxPolicy.REQUIRE
        }
        return cfg
    }

    /**
     * Parse the iceServers JSON array. Each entry can be a string ("stun:...")
     * for shorthand or an object with url/username/credential fields.
     */
    private fun parseIceServers(jsonStr: String): List<PeerConnection.IceServer> {
        if (jsonStr.isBlank() || jsonStr == "null") return emptyList()
        val element = runCatching { Json.parseToJsonElement(jsonStr) }.getOrNull() ?: return emptyList()
        if (element !is kotlinx.serialization.json.JsonArray) return emptyList()
        val out = mutableListOf<PeerConnection.IceServer>()
        for (entry in element) {
            val builder = when (entry) {
                is kotlinx.serialization.json.JsonPrimitive -> PeerConnection.IceServer.builder(entry.content)
                is JsonObject -> {
                    val url = entry["url"]?.toString()?.trim('"') ?: continue
                    val b = PeerConnection.IceServer.builder(url)
                    entry["username"]?.toString()?.trim('"')?.let { b.setUsername(it) }
                    entry["credential"]?.toString()?.trim('"')?.let { b.setPassword(it) }
                    b
                }
                else -> continue
            }
            out += builder.createIceServer()
        }
        return out
    }

    /** Receive one signaling envelope from the admin (via broker). */
    private fun onIncoming(env: SignalingEnvelope) {
        val pc = peerConnection ?: return
        when (env.type) {
            "sdp" -> {
                val sdp = Json.decodeFromJsonElement(SdpMessage.serializer(), env.payload ?: return)
                val type = when (sdp.type.lowercase()) {
                    "offer" -> SessionDescription.Type.OFFER
                    "answer" -> SessionDescription.Type.ANSWER
                    else -> return
                }
                pc.setRemoteDescription(SimpleSdpObserver(), SessionDescription(type, sdp.sdp))
                if (type == SessionDescription.Type.OFFER) {
                    // Admin initiated; respond with answer.
                    pc.createAnswer(object : SimpleSdpObserver() {
                        override fun onCreateSuccess(desc: SessionDescription) {
                            pc.setLocalDescription(SimpleSdpObserver(), desc)
                            signaling.sendEnvelope("sdp", SdpMessage(sdp = desc.description, type = "answer"))
                        }
                    }, MediaConstraints())
                }
            }
            "ice" -> {
                val ice = Json.decodeFromJsonElement(IceCandidateMessage.serializer(), env.payload ?: return)
                pc.addIceCandidate(
                    IceCandidate(ice.sdp_mid ?: "", ice.sdp_m_line_index ?: 0, ice.candidate)
                )
            }
            "control" -> {
                // No-op for now; e.g. could honor a "pause" / "resume".
            }
        }
    }

    private fun createAndSendOffer() {
        val pc = peerConnection ?: return
        pc.createOffer(object : SimpleSdpObserver() {
            override fun onCreateSuccess(desc: SessionDescription) {
                pc.setLocalDescription(SimpleSdpObserver(), desc)
                signaling.sendEnvelope("sdp", SdpMessage(sdp = desc.description, type = "offer"))
            }
        }, MediaConstraints())
    }

    private fun attachInputChannel(dc: DataChannel) {
        inputChannel = dc
        dc.registerObserver(object : DataChannel.Observer {
            override fun onBufferedAmountChange(p0: Long) {}
            override fun onStateChange() {}
            override fun onMessage(buffer: DataChannel.Buffer) {
                val text = StandardCharsets.UTF_8.decode(buffer.data).toString()
                val msg = runCatching {
                    Json.decodeFromString(InputEventMessage.serializer(), text)
                }.getOrNull() ?: return
                injector.dispatch(msg)
            }
        })
    }

    private companion object {
        const val TAG = "RemoteSupportEngine"
        // Capture defaults — admin can override via signaling later when we
        // add adaptive bitrate.
        const val SCREEN_WIDTH = 1280
        const val SCREEN_HEIGHT = 720
        const val SCREEN_FPS = 15
    }
}

// --- Lightweight WebRTC observer no-ops used by the engine ---

private open class SimplePeerObserver : PeerConnection.Observer {
    override fun onSignalingChange(s: PeerConnection.SignalingState) {}
    override fun onIceConnectionChange(s: PeerConnection.IceConnectionState) {}
    override fun onIceConnectionReceivingChange(r: Boolean) {}
    override fun onIceGatheringChange(s: PeerConnection.IceGatheringState) {}
    override fun onIceCandidate(c: IceCandidate) {}
    override fun onIceCandidatesRemoved(c: Array<out IceCandidate>?) {}
    override fun onAddStream(s: org.webrtc.MediaStream?) {}
    override fun onRemoveStream(s: org.webrtc.MediaStream?) {}
    override fun onDataChannel(dc: DataChannel) {}
    override fun onRenegotiationNeeded() {}
    override fun onAddTrack(rec: org.webrtc.RtpReceiver, ms: Array<out org.webrtc.MediaStream>?) {}
}

private open class SimpleSdpObserver : SdpObserver {
    override fun onCreateSuccess(p0: SessionDescription?) {}
    override fun onSetSuccess() {}
    override fun onCreateFailure(p0: String?) {}
    override fun onSetFailure(p0: String?) {}
}
