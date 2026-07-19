package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"go.uber.org/zap"

	"github.com/openidx/openidx/agent/internal/remotesupport"
)

// wsSignalConn adapts a gorilla WebSocket to remotesupport.SignalConn.
type wsSignalConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *wsSignalConn) ReadJSON(v interface{}) error { return w.conn.ReadJSON(v) }
func (w *wsSignalConn) WriteJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn.WriteJSON(v)
}
func (w *wsSignalConn) Close() error { return w.conn.Close() }

// runRemoteSupport dials the agent signaling WebSocket for the given session and
// streams the screen to the admin. It is a no-op in builds without a capture
// stack (NewScreenSource returns a stub that sends no frames), but the peer
// still connects and honors input/control_state, so this is safe to always run.
//
// Called once per session id (tracked by handledSessions) after consent is
// granted (or immediately when consent is not required).
func (a *Agent) runRemoteSupport(rs *RemoteSupportBlock) {
	if rs == nil || rs.SessionID == "" || rs.WSPath == "" {
		return
	}
	if a.handledSessions == nil {
		a.handledSessions = map[string]bool{}
	}
	if a.handledSessions[rs.SessionID] {
		return
	}
	a.handledSessions[rs.SessionID] = true

	go func() {
		if err := a.streamRemoteSupport(context.Background(), rs); err != nil {
			a.logger.Warn("remote-support session ended", zap.String("session_id", rs.SessionID), zap.Error(err))
		}
	}()
}

// streamRemoteSupport dials the signaling WS (auth via agent headers) and runs
// the device peer until the session ends.
func (a *Agent) streamRemoteSupport(ctx context.Context, rs *RemoteSupportBlock) error {
	wsURL, err := a.signalURL(rs.WSPath)
	if err != nil {
		return err
	}

	hdr := http.Header{}
	hdr.Set("X-Agent-ID", a.config.AgentID)
	hdr.Set("X-Auth-Token", a.config.AuthToken)

	dialer := *websocket.DefaultDialer
	if strings.HasPrefix(wsURL, "wss://") {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: a.config.InsecureSkipVerify}
	}
	conn, _, err := dialer.DialContext(ctx, wsURL, hdr)
	if err != nil {
		return err
	}
	sig := &wsSignalConn{conn: conn}
	defer sig.Close()

	src, err := remotesupport.NewScreenSource(a.remoteSupportFPS())
	if err != nil {
		return err
	}

	peer := remotesupport.NewPeer(remotesupport.PeerConfig{
		ICEServers: parseICEServers(rs.ICEServersRaw),
		Source:     src,
		Input:      a.inputSink(), // OS input injector, or no-op
		Logger:     a.logger,
	})
	defer peer.Close()

	a.logger.Info("remote-support: streaming screen", zap.String("session_id", rs.SessionID), zap.String("mode", rs.Mode))
	return peer.Run(sig)
}

// signalURL turns the server-relative ws_path into an absolute ws(s):// URL
// using the agent's configured server URL.
func (a *Agent) signalURL(wsPath string) (string, error) {
	base, err := url.Parse(a.config.ServerURL)
	if err != nil {
		return "", err
	}
	scheme := "wss"
	if base.Scheme == "http" {
		scheme = "ws"
	}
	u := url.URL{Scheme: scheme, Host: base.Host, Path: wsPath}
	return u.String(), nil
}

// remoteSupportFPS is the capture frame rate (overridable later via config).
func (a *Agent) remoteSupportFPS() int { return 10 }

// inputSink returns the OS input injector when one is wired, else a no-op.
// (A Windows SendInput-backed sink can be installed via Agent.RemoteInputSink.)
func (a *Agent) inputSink() remotesupport.InputSink {
	if a.RemoteInputSink != nil {
		return a.RemoteInputSink
	}
	return nil // NewPeer defaults to a no-op sink
}

// parseICEServers converts the raw ice_servers JSON (array of {urls,...}) from
// the server into pion ICEServer structs. Empty/invalid yields no servers
// (LAN / Ziti-overlay-only), which is valid.
func parseICEServers(raw json.RawMessage) []webrtc.ICEServer {
	if len(raw) == 0 {
		return nil
	}
	var arr []struct {
		URLs       interface{} `json:"urls"`
		Username   string      `json:"username"`
		Credential string      `json:"credential"`
	}
	if json.Unmarshal(raw, &arr) != nil {
		return nil
	}
	var out []webrtc.ICEServer
	for _, s := range arr {
		var urls []string
		switch v := s.URLs.(type) {
		case string:
			urls = []string{v}
		case []interface{}:
			for _, u := range v {
				if us, ok := u.(string); ok {
					urls = append(urls, us)
				}
			}
		}
		if len(urls) == 0 {
			continue
		}
		srv := webrtc.ICEServer{URLs: urls}
		if s.Username != "" {
			srv.Username = s.Username
			srv.Credential = s.Credential
		}
		out = append(out, srv)
	}
	return out
}
