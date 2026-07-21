package access

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// newBrokerTestServer stands up an httptest server whose only job is to upgrade
// incoming connections and hand them to runPeer with the requested role. This
// exercises the real broker relay + replay path without a database.
func newBrokerTestServer(t *testing.T) (*RemoteSupportHandler, *httptest.Server) {
	t.Helper()
	h := NewRemoteSupportHandler(zap.NewNop(), nil, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := h.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/agent/")
		h.runPeer(r.Context(), id, conn, peerAgent)
	})
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := h.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/admin/")
		h.runPeer(r.Context(), id, conn, peerAdmin)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return h, srv
}

func dialWS(t *testing.T, srv *httptest.Server, path string) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + path
	c, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestBrokerLateJoinReplaysOffer is the regression test for the bug where a
// device that connects and emits its SDP OFFER before the admin viewer joins
// would have that OFFER silently dropped, leaving the viewer stuck on
// "signaling channel closed". The broker must buffer the offer and replay it
// to the admin when it connects later.
func TestBrokerLateJoinReplaysOffer(t *testing.T) {
	_, srv := newBrokerTestServer(t)
	sid := "sess-late-join"

	// DEVICE connects first and immediately sends its OFFER + an ICE candidate,
	// before any admin viewer is present.
	dev := dialWS(t, srv, "/agent/"+sid)
	if err := dev.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp","payload":"OFFER"}`)); err != nil {
		t.Fatalf("device write offer: %v", err)
	}
	if err := dev.WriteMessage(websocket.TextMessage, []byte(`{"type":"ice","payload":"CAND1"}`)); err != nil {
		t.Fatalf("device write ice: %v", err)
	}
	// Give the broker a moment to record the replay buffer.
	time.Sleep(100 * time.Millisecond)

	// ADMIN joins late. It must receive the buffered OFFER + ICE via replay.
	adm := dialWS(t, srv, "/admin/"+sid)
	got := readN(t, adm, 2)
	if !containsMsg(got, "OFFER") {
		t.Errorf("late-joining admin never received the buffered OFFER; got %v", got)
	}
	if !containsMsg(got, "CAND1") {
		t.Errorf("late-joining admin never received the buffered ICE candidate; got %v", got)
	}

	// And live relay still works: admin -> device after both connected.
	if err := adm.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp","payload":"ANSWER"}`)); err != nil {
		t.Fatalf("admin write answer: %v", err)
	}
	live := readN(t, dev, 1)
	if !containsMsg(live, "ANSWER") {
		t.Errorf("device never received live-relayed ANSWER; got %v", live)
	}
}

// TestBrokerLiveRelayBothOrders proves ordinary (both-present) relay still
// works in both directions when the admin connects first.
func TestBrokerLiveRelayBothPresent(t *testing.T) {
	_, srv := newBrokerTestServer(t)
	sid := "sess-live"

	adm := dialWS(t, srv, "/admin/"+sid)
	dev := dialWS(t, srv, "/agent/"+sid)
	time.Sleep(50 * time.Millisecond)

	if err := dev.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp","payload":"OFFER"}`)); err != nil {
		t.Fatalf("device write: %v", err)
	}
	if !containsMsg(readN(t, adm, 1), "OFFER") {
		t.Error("admin did not receive device OFFER via live relay")
	}
	if err := adm.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp","payload":"ANSWER"}`)); err != nil {
		t.Fatalf("admin write: %v", err)
	}
	if !containsMsg(readN(t, dev, 1), "ANSWER") {
		t.Error("device did not receive admin ANSWER via live relay")
	}
}

// TestBrokerAgentReconnectNoStaleReplay is the regression test for the bug
// where a reconnecting device received STALE signaling from a previous
// negotiation carrying an old ICE ufrag, making ICE reject the answer
// (stable->SetRemote(answer)->stable) and drop every candidate so the peer
// looped forever. Only the agent's CURRENT offer may be replayed, and only to
// a joining admin; a reconnecting agent gets a clean slate.
func TestBrokerAgentReconnectNoStaleReplay(t *testing.T) {
	_, srv := newBrokerTestServer(t)
	sid := "sess-reconnect"

	// First negotiation: device sends offer#1, admin answers.
	dev1 := dialWS(t, srv, "/agent/"+sid)
	_ = dev1.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp","payload":"OFFER1"}`))
	time.Sleep(50 * time.Millisecond)
	adm := dialWS(t, srv, "/admin/"+sid)
	_ = readN(t, adm, 1) // consumes OFFER1
	_ = adm.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp","payload":"ANSWER1"}`))
	_ = readN(t, dev1, 1) // dev1 gets ANSWER1
	_ = dev1.Close()      // device's peer closes (ICE timeout)
	time.Sleep(100 * time.Millisecond)

	// Device reconnects: it must receive NO replayed signaling (a stale ANSWER1
	// would carry an old ufrag). The agent side is never replayed to.
	dev2 := dialWS(t, srv, "/agent/"+sid)
	_ = dev2.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if _, data, err := dev2.ReadMessage(); err == nil {
		t.Errorf("reconnected device received unexpected replayed signaling: %q", string(data))
	}

	// A fresh admin joining now must get the CURRENT OFFER2, never the stale one.
	_ = dev2.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp","payload":"OFFER2"}`))
	time.Sleep(50 * time.Millisecond)
	adm2 := dialWS(t, srv, "/admin/"+sid)
	got := readN(t, adm2, 1)
	if !containsMsg(got, "OFFER2") {
		t.Errorf("fresh admin did not get the current OFFER2; got %v", got)
	}
	if containsMsg(got, "OFFER1") {
		t.Errorf("fresh admin got the STALE OFFER1; got %v", got)
	}
}

// TestBrokerRelayForwardsBinaryVideo proves the broker forwards binary frames
// (the relay transport's VP8 video) device->admin verbatim, preserving the
// binary opcode. This is the core of the relay transport that the admin console
// now defaults to on Chromium.
func TestBrokerRelayForwardsBinaryVideo(t *testing.T) {
	_, srv := newBrokerTestServer(t)
	sid := "sess-relay-video"

	adm := dialWS(t, srv, "/admin/"+sid)
	dev := dialWS(t, srv, "/agent/"+sid)
	time.Sleep(50 * time.Millisecond)

	// Device sends a binary VP8 keyframe: [flags byte][payload].
	frame := append([]byte{0x01}, []byte("VP8-KEYFRAME-BYTES")...)
	if err := dev.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		t.Fatalf("device write binary: %v", err)
	}

	_ = adm.SetReadDeadline(time.Now().Add(3 * time.Second))
	mt, data, err := adm.ReadMessage()
	if err != nil {
		t.Fatalf("admin read binary: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("expected binary opcode, got %d", mt)
	}
	if string(data) != string(frame) {
		t.Fatalf("binary frame corrupted in relay: got %q want %q", data, frame)
	}

	// Input travels the other way as text JSON (admin->device).
	if err := adm.WriteMessage(websocket.TextMessage, []byte(`{"event":"tap","x":500,"y":500}`)); err != nil {
		t.Fatalf("admin write input: %v", err)
	}
	if !containsMsg(readN(t, dev, 1), "tap") {
		t.Error("device did not receive relayed input JSON")
	}
}

// TestBrokerDoesNotReplayBinaryVideo proves binary video frames are NOT buffered
// for replay: a late-joining admin must not receive a burst of stale VP8 frames
// (it waits for a fresh keyframe), and the replay buffer must not grow with
// video. Only text signaling is replayed.
func TestBrokerDoesNotReplayBinaryVideo(t *testing.T) {
	_, srv := newBrokerTestServer(t)
	sid := "sess-no-binary-replay"

	// Device connects first and streams several binary frames + one text control
	// message before any admin is present.
	dev := dialWS(t, srv, "/agent/"+sid)
	for i := 0; i < 5; i++ {
		frame := append([]byte{0x00}, []byte("DELTA")...)
		if err := dev.WriteMessage(websocket.BinaryMessage, frame); err != nil {
			t.Fatalf("device write binary %d: %v", i, err)
		}
	}
	if err := dev.WriteMessage(websocket.TextMessage, []byte(`{"type":"hello","payload":"READY"}`)); err != nil {
		t.Fatalf("device write text: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Admin joins late. It must receive the replayed TEXT signaling but NONE of
	// the stale binary frames.
	adm := dialWS(t, srv, "/admin/"+sid)
	_ = adm.SetReadDeadline(time.Now().Add(1 * time.Second))
	sawText := false
	for {
		mt, data, err := adm.ReadMessage()
		if err != nil {
			break // deadline: no more buffered messages
		}
		if mt == websocket.BinaryMessage {
			t.Fatalf("late admin received a STALE binary video frame (%q); binary must not be replayed", data)
		}
		if mt == websocket.TextMessage && strings.Contains(string(data), "READY") {
			sawText = true
		}
	}
	if !sawText {
		t.Error("late admin did not receive the replayed text signaling")
	}
}

func readN(t *testing.T, c *websocket.Conn, n int) []string {
	t.Helper()
	var out []string
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < n; i++ {
		_, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read %d/%d: %v", i+1, n, err)
		}
		out = append(out, string(data))
	}
	return out
}

func containsMsg(msgs []string, needle string) bool {
	for _, m := range msgs {
		if strings.Contains(m, needle) {
			return true
		}
	}
	return false
}
