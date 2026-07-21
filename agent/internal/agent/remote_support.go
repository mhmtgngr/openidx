package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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
		// Reconnect loop. The device typically discovers a session (via its 5s
		// config poll) and dials in BEFORE the admin has opened the viewer. In
		// that case the peer connects to the broker, emits its offer, and — with
		// no admin peer to answer — eventually closes. A one-shot stream would
		// then give up forever, so a viewer that opens a moment later finds no
		// device peer. Instead, re-establish the peer as long as the session is
		// still being served in /agent/config, with a short backoff. The loop
		// ends when the session disappears from config (ended/expired) or the
		// agent shuts down.
		const backoff = 3 * time.Second
		for {
			err := a.streamRemoteSupport(context.Background(), rs)
			if err != nil {
				a.logger.Info("remote-support peer closed; will re-check session",
					zap.String("session_id", rs.SessionID), zap.Error(err))
			}
			// Stop retrying once the server no longer advertises this session.
			if !a.remoteSupportSessionLive(rs.SessionID) {
				a.logger.Info("remote-support session no longer live; stopping",
					zap.String("session_id", rs.SessionID))
				break
			}
			time.Sleep(backoff)
		}
		// Allow a future session with the same id to be handled again (ids are
		// unique per session, so this mainly guards against map growth).
		delete(a.handledSessions, rs.SessionID)
	}()
}

// remoteSupportSessionLive reports whether the server is still advertising the
// given remote-support session. It reads the agent's cached serverCfg — kept
// fresh by the main SyncConfig loop (which polls every 5s while a session is
// attached) — instead of issuing its own /agent/config fetch on every reconnect
// cycle. That avoids doubling the config request rate during the pending-session
// reconnect churn. Falls back to a direct fetch only if the cache is empty
// (e.g. the very first cycle before the main loop has synced).
func (a *Agent) remoteSupportSessionLive(sessionID string) bool {
	if a.serverCfg != nil {
		if rs := a.serverCfg.RemoteSupport; rs != nil {
			return rs.SessionID == sessionID
		}
		// Cache is populated but shows no session — trust it (session ended).
		if len(a.serverCfg.Checks) > 0 {
			return false
		}
	}
	// Cold cache: do a one-off direct fetch.
	data, err := a.client.GetConfig()
	if err != nil {
		return false
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	return cfg.RemoteSupport != nil && cfg.RemoteSupport.SessionID == sessionID
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

	conn, err := a.dialSignaling(ctx, rs, wsURL, hdr)
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
		Input:      a.trackingInputSink(), // wraps the OS sink to track control state
		Logger:     a.logger,
	})
	defer peer.Close()

	// Banner state for the tray: active for the session's lifetime.
	a.remoteSupportActive.Store(true)
	defer func() {
		a.remoteSupportActive.Store(false)
		a.remoteSupportControlled.Store(false)
	}()

	a.logger.Info("remote-support: streaming screen", zap.String("session_id", rs.SessionID), zap.String("mode", rs.Mode))
	return peer.Run(sig)
}

// RemoteSupportState returns the live banner flags for the tray IPC status:
// active (a session is streaming) and controlled (the admin currently holds
// control). Safe to call from any goroutine.
func (a *Agent) RemoteSupportState() (active, controlled bool) {
	return a.remoteSupportActive.Load(), a.remoteSupportControlled.Load()
}

// trackingInputSink wraps the OS input sink so the agent can mirror the admin's
// control_state into remoteSupportControlled (for the tray banner) while still
// delegating actual input to the underlying sink.
func (a *Agent) trackingInputSink() remotesupport.InputSink {
	return &controlTrackingSink{agent: a, inner: a.inputSink()}
}

type controlTrackingSink struct {
	agent *Agent
	inner remotesupport.InputSink
}

func (s *controlTrackingSink) Apply(ev remotesupport.InputEvent) {
	if s.inner != nil {
		s.inner.Apply(ev)
	}
}

func (s *controlTrackingSink) SetControlActive(active bool) {
	s.agent.remoteSupportControlled.Store(active)
	if s.inner != nil {
		s.inner.SetControlActive(active)
	}
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

// dialSignaling opens the remote-support signaling WebSocket. When the server
// advertised a Ziti service (rs.ZitiService) and the agent has a Ziti-backed
// transport, it dials the broker over the OVERLAY (zero-trust, no public port):
// zitiCtx.Dial(service) yields a net.Conn on which we run the WebSocket
// handshake. On any Ziti failure — or when no service is advertised — it falls
// back to the public WSS dial, so same-LAN / edge deployments are unchanged.
func (a *Agent) dialSignaling(ctx context.Context, rs *RemoteSupportBlock, wsURL string, hdr http.Header) (*websocket.Conn, error) {
	if rs.ZitiService != "" && a.client != nil {
		if netConn, derr := a.client.DialServiceConn(rs.ZitiService); derr == nil {
			// The overlay terminates at the broker; use a fixed host in the URL
			// (the connection is already routed by Ziti, not by DNS/TLS SNI).
			ovURL := "ws://openidx-access" + rs.WSPath
			d := websocket.Dialer{
				NetDial: func(network, addr string) (net.Conn, error) { return netConn, nil },
			}
			conn, _, werr := d.DialContext(ctx, ovURL, hdr)
			if werr == nil {
				a.logger.Info("remote-support: signaling over Ziti overlay",
					zap.String("service", rs.ZitiService), zap.String("session_id", rs.SessionID))
				return conn, nil
			}
			_ = netConn.Close()
			a.logger.Warn("remote-support: Ziti signaling dial failed; falling back to public WSS",
				zap.String("service", rs.ZitiService), zap.Error(werr))
		} else {
			a.logger.Warn("remote-support: Ziti service dial unavailable; falling back to public WSS",
				zap.String("service", rs.ZitiService), zap.Error(derr))
		}
	}

	dialer := *websocket.DefaultDialer
	if strings.HasPrefix(wsURL, "wss://") {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: a.config.InsecureSkipVerify}
	}
	conn, _, err := dialer.DialContext(ctx, wsURL, hdr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// remoteSupportFPS is the capture frame rate (overridable later via config).
func (a *Agent) remoteSupportFPS() int { return 10 }

// inputSink returns the input injector for an active session: an explicitly
// installed RemoteInputSink, else the OS injector (Windows SendInput), else nil
// (view-only — the peer still streams, input is simply not applied).
func (a *Agent) inputSink() remotesupport.InputSink {
	if a.RemoteInputSink != nil {
		return a.RemoteInputSink
	}
	return remotesupport.NewWindowsInputSink() // nil off Windows
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
