// Command e2e-screenshare proves the device WebRTC peer connects to the LIVE
// OpenIDX signaling broker end-to-end: it starts a session (admin), runs the
// device peer against the agent WS, answers from a pion admin peer, and reports
// when the connection reaches "connected". Uses a synthetic video source (no
// libvpx needed). Run against the deployed access-service.
//
//	go run ./cmd/e2e-screenshare -token <agent-token> -at <admin-bearer>
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/remotesupport"
)

type env struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}
type sdpP struct{ SDP, Type string }
type iceP struct {
	Candidate     string `json:"candidate"`
	SDPMid        string `json:"sdp_mid"`
	SDPMLineIndex uint16 `json:"sdp_m_line_index"`
}

type wsConn struct {
	c  *websocket.Conn
	mu sync.Mutex
}

func (w *wsConn) ReadJSON(v interface{}) error { return w.c.ReadJSON(v) }
func (w *wsConn) WriteJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.c.WriteJSON(v)
}
func (w *wsConn) Close() error { return w.c.Close() }

func main() {
	host := flag.String("host", "127.0.0.1:8007", "access-service host:port (direct)")
	agentID := flag.String("agent", "agent-e2e-test", "agent id")
	token := flag.String("token", "", "agent auth token (plaintext)")
	sessionID := flag.String("session", "", "existing remote-support session id")
	flag.Parse()
	if *token == "" || *sessionID == "" {
		fmt.Println("usage: -token <agent-token> -session <session-id> [-agent id] [-host h:p]")
		os.Exit(2)
	}
	log, _ := zap.NewDevelopment()

	// --- DEVICE side: dial the agent signaling WS + run the peer. ---
	dev := websocket.DefaultDialer
	dev.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	hdr := http.Header{}
	hdr.Set("X-Agent-ID", *agentID)
	hdr.Set("X-Auth-Token", *token)
	dURL := fmt.Sprintf("ws://%s/api/v1/access/agent/remote-support/sessions/%s/ws", *host, *sessionID)
	dc, _, err := dev.Dial(dURL, hdr)
	if err != nil {
		fmt.Println("DEVICE dial failed:", err)
		os.Exit(1)
	}
	fmt.Println("DEVICE: signaling WS connected ->", dURL)

	src := remotesupport.NewSyntheticSource(50*time.Millisecond, []byte{0x00})
	peer := remotesupport.NewPeer(remotesupport.PeerConfig{Source: src, Logger: log})
	go func() {
		if e := peer.Run(&wsConn{c: dc}); e != nil {
			fmt.Println("DEVICE peer ended:", e)
		}
	}()

	// --- ADMIN side: dial the admin signaling WS + answer. ---
	adm := websocket.DefaultDialer
	adm.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	ahdr := http.Header{}
	// Admin WS carries the bearer via subprotocol (browsers can't set headers).
	aURL := fmt.Sprintf("ws://%s/api/v1/access/remote-support/sessions/%s/ws", *host, *sessionID)
	ac, _, err := adm.Dial(aURL, ahdr)
	if err != nil {
		fmt.Println("ADMIN dial failed:", err)
		os.Exit(1)
	}
	fmt.Println("ADMIN: signaling WS connected ->", aURL)
	admin, _ := webrtc.NewPeerConnection(webrtc.Configuration{})
	defer admin.Close()

	connected := make(chan struct{})
	var once sync.Once
	admin.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		fmt.Println("ADMIN peer state:", s)
		if s == webrtc.PeerConnectionStateConnected {
			once.Do(func() { close(connected) })
		}
	})
	admin.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		fmt.Println("ADMIN: RECEIVING video track:", tr.Codec().MimeType)
	})
	admin.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		ci := c.ToJSON()
		mid := ""
		if ci.SDPMid != nil {
			mid = *ci.SDPMid
		}
		var idx uint16
		if ci.SDPMLineIndex != nil {
			idx = *ci.SDPMLineIndex
		}
		raw, _ := json.Marshal(iceP{Candidate: ci.Candidate, SDPMid: mid, SDPMLineIndex: idx})
		_ = ac.WriteJSON(env{Type: "ice", Payload: raw})
	})
	go func() {
		for {
			var e env
			if err := ac.ReadJSON(&e); err != nil {
				return
			}
			switch e.Type {
			case "sdp":
				var sp struct{ SDP, Type string }
				_ = json.Unmarshal(e.Payload, &sp)
				if sp.Type == "offer" {
					fmt.Println("ADMIN: received OFFER from device")
					_ = admin.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sp.SDP})
					ans, _ := admin.CreateAnswer(nil)
					_ = admin.SetLocalDescription(ans)
					raw, _ := json.Marshal(sdpP{SDP: ans.SDP, Type: "answer"})
					_ = ac.WriteJSON(env{Type: "sdp", Payload: raw})
					fmt.Println("ADMIN: sent ANSWER")
				}
			case "ice":
				var ip iceP
				if json.Unmarshal(e.Payload, &ip) == nil && ip.Candidate != "" {
					mid := ip.SDPMid
					idx := ip.SDPMLineIndex
					_ = admin.AddICECandidate(webrtc.ICECandidateInit{Candidate: ip.Candidate, SDPMid: &mid, SDPMLineIndex: &idx})
				}
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	select {
	case <-connected:
		fmt.Println("\n✅ END-TO-END: device peer connected to the live broker and the admin peer — video pipeline established.")
		os.Exit(0)
	case <-ctx.Done():
		fmt.Println("\n❌ timed out waiting for the peer connection")
		os.Exit(1)
	}
}
