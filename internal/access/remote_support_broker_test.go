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
