// Package access — clientless in-browser SSH over a WebSocket->TCP relay.
//
// This is the "wasm-ssh" renderer's server side (dark-platform / clientless
// remote access). A PAM entry whose renderer is 'wasm-ssh' is opened by an
// xterm.js terminal in the browser; that terminal connects to
//
//	GET /api/v1/access/pam/entries/:id/ws?proto=ssh
//
// and this handler:
//  1. Runs the SAME permission + approval gate as handlePamConnect
//     (pamEntryAllowed + checkAndConsumePamApproval) BEFORE upgrading the
//     socket — an unauthorized caller never reaches the target.
//  2. Resolves the entry's credential (vault) server-side and opens an SSH
//     session to the entry's dialTarget() (loopback intercept in ziti reach
//     mode, so the ziti-tunnel carries it over the overlay; real host in
//     direct mode). The plaintext credential never leaves the process.
//  3. Bridges the WebSocket <-> the SSH channel: browser stdin -> SSH, SSH
//     stdout/stderr -> browser, and forwards terminal resize messages.
//  4. Records the session in pam_entry_sessions and audits start/end.
//
// No guacd in the path; no client installed on the user's machine. The browser
// tab is the SSH client.
package access

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"github.com/openidx/openidx/internal/common/orgctx"
)

// wsRelayUpgrader upgrades the browser terminal connection. The OAuth Bearer is
// already validated by the API middleware before this handler runs, and the
// permission gate below is the authorization check, so origin is permitted (the
// admin console and the mobile app are both first-party).
var wsRelayUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// wsClientMessage is a control/data frame sent by the browser terminal.
// type "data" carries keystrokes; type "resize" carries new dimensions.
type wsClientMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// handlePamWSConnect is GET /pam/entries/:id/ws — the clientless SSH relay.
// Only proto=ssh is supported today (novnc/rdp relays are a later slice).
func (s *Service) handlePamWSConnect(c *gin.Context) {
	entryID := c.Param("id")
	proto := c.Query("proto")
	if proto == "" {
		proto = "ssh"
	}
	if proto != "ssh" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported proto (only 'ssh' is implemented)"})
		return
	}

	ctx := c.Request.Context()
	org, err := orgctx.From(ctx)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "organization context required"})
		return
	}
	userID := c.GetString("user_id")
	isAdmin := s.pamCallerIsAdmin(c)

	entry, typeInfo, ok := s.loadPamLaunchEntry(c, org.ID, entryID)
	if !ok {
		return // loadPamLaunchEntry already wrote the error
	}
	if typeInfo.Protocol != "ssh" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entry is not an SSH session"})
		return
	}

	// Permission gate — identical to handlePamConnect. MUST run before upgrade.
	if !isAdmin {
		allowed, aclErr := s.pamEntryAllowed(ctx, org.ID, entryID, userID, pamCallerRoles(c), "connect")
		if aclErr != nil {
			s.logger.Error("ws-connect: ACL check failed", zap.Error(aclErr))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check permissions"})
			return
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "not permitted"})
			return
		}
	}
	// Approval gate — single-use, atomically consumed (admins bypass their own).
	if entry.RequireApproval && !isAdmin {
		consumed, gateErr := s.checkAndConsumePamApproval(ctx, entryID, userID)
		if gateErr != nil || !consumed {
			c.JSON(http.StatusForbidden, gin.H{"error": "session requires approval", "approval_required": true})
			return
		}
	}

	// Resolve credential (server-side; plaintext never leaves this process).
	target, terr := s.resolvePamLaunchTarget(ctx, org.ID, &entry)
	if terr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "credential unavailable"})
		return
	}
	var cred []byte
	var secretType string
	if target.SecretID != "" && s.vaultSvc != nil {
		bctx := orgctx.WithBypassRLS(ctx)
		cred, err = s.vaultSvc.Use(bctx, target.SecretID)
		if err != nil {
			s.logger.Warn("ws-connect: vault credential unavailable", zap.String("secret_id", target.SecretID), zap.Error(err))
			c.JSON(http.StatusForbidden, gin.H{"error": "credential unavailable"})
			return
		}
		//orgscope:ignore vault_secrets SELECT under bypass-RLS to determine injection field
		_ = s.db.Pool.QueryRow(bctx, `SELECT type FROM vault_secrets WHERE id=$1`, target.SecretID).Scan(&secretType)
	}

	username := target.Username
	if username == "" {
		username = "root"
	}
	host, port := entry.dialTarget()

	// Build the SSH client config from the injected credential before the
	// upgrade, so a credential failure is a clean HTTP error (not a socket).
	sshConfig, cfgErr := buildSSHClientConfig(username, secretType, cred)
	// Zero the plaintext as soon as the signer/password is built.
	for i := range cred {
		cred[i] = 0
	}
	if cfgErr != nil {
		s.logger.Warn("ws-connect: ssh config build failed", zap.Error(cfgErr))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential for ssh"})
		return
	}

	// Dial the target (loopback intercept in ziti mode -> ziti-tunnel -> overlay).
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	sshClient, dialErr := sshDialWithTimeout("tcp", addr, sshConfig, 15*time.Second)
	if dialErr != nil {
		s.logger.Warn("ws-connect: ssh dial failed", zap.String("addr", addr), zap.Error(dialErr))
		c.JSON(http.StatusBadGateway, gin.H{"error": "could not reach target"})
		return
	}
	defer sshClient.Close()

	// Everything below is committed: upgrade the socket and bridge.
	wsConn, upErr := wsRelayUpgrader.Upgrade(c.Writer, c.Request, nil)
	if upErr != nil {
		return // Upgrade writes its own error
	}
	defer wsConn.Close()

	injected := secretType != "" || username != ""
	sessionID := s.recordPamLaunch(c, org.ID, &entry, "ssh", "", injected, "")
	s.logAuditEvent(c, "pam.ws_connect", entryID, "pam_entry", map[string]interface{}{
		"entry_id": entryID, "renderer": "wasm-ssh", "protocol": "ssh",
		"user_id": userID, "session_id": sessionID, "outcome": "started",
	})
	defer s.logAuditEvent(c, "pam.ws_disconnect", entryID, "pam_entry", map[string]interface{}{
		"entry_id": entryID, "user_id": userID, "session_id": sessionID, "outcome": "ended",
	})

	bridgeSSHOverWebSocket(wsConn, sshClient, s.logger)
}

// buildSSHClientConfig builds an ssh.ClientConfig from an injected credential.
// A 'ssh_key' secret is used as a private key; anything else is a password.
// HostKeyCallback is InsecureIgnoreHostKey because the connection reaches the
// target over the Ziti overlay (identity-scoped, no MITM surface) or a trusted
// direct target; host-key pinning per entry is a follow-up.
func buildSSHClientConfig(username, secretType string, cred []byte) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // overlay-scoped; per-entry pinning is a follow-up
		Timeout:         15 * time.Second,
	}
	if len(cred) == 0 {
		return nil, fmt.Errorf("no credential to authenticate")
	}
	if secretType == "ssh_key" {
		signer, err := ssh.ParsePrivateKey(cred)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		pw := string(cred)
		cfg.Auth = []ssh.AuthMethod{ssh.Password(pw)}
	}
	return cfg, nil
}

// sshDialWithTimeout is a small wrapper so tests can stub the dial.
var sshDialWithTimeout = func(network, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// bridgeSSHOverWebSocket opens an interactive SSH shell with a PTY and pumps
// bytes both ways until either side closes. Browser frames are JSON control
// messages (data/resize); SSH output is sent as binary WS frames.
func bridgeSSHOverWebSocket(wsConn *websocket.Conn, sshClient *ssh.Client, logger *zap.Logger) {
	session, err := sshClient.NewSession()
	if err != nil {
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("\r\n[openidx] could not open ssh session\r\n"))
		return
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("\r\n[openidx] pty request failed\r\n"))
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return
	}
	if err := session.Shell(); err != nil {
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("\r\n[openidx] shell start failed\r\n"))
		return
	}

	done := make(chan struct{})
	// SSH stdout/stderr -> browser (binary frames).
	pump := func(r interface{ Read([]byte) (int, error) }) {
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				if werr := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		select {
		case <-done:
		default:
			close(done)
		}
	}
	go pump(stdout)
	go pump(stderr)

	// Browser -> SSH stdin (+ resize).
	go func() {
		for {
			mt, data, rerr := wsConn.ReadMessage()
			if rerr != nil {
				break
			}
			if mt == websocket.BinaryMessage {
				_, _ = stdin.Write(data)
				continue
			}
			var msg wsClientMessage
			if json.Unmarshal(data, &msg) == nil {
				switch msg.Type {
				case "data":
					_, _ = stdin.Write([]byte(msg.Data))
				case "resize":
					if msg.Cols > 0 && msg.Rows > 0 {
						_ = session.WindowChange(msg.Rows, msg.Cols)
					}
				}
			} else {
				_, _ = stdin.Write(data)
			}
		}
		select {
		case <-done:
		default:
			close(done)
		}
	}()

	<-done
	_ = session.Signal(ssh.SIGTERM)
}

// loadPamLaunchEntry loads the pam_entries columns the launch/relay paths need,
// resolving the entry type. It writes the appropriate HTTP error and returns
// ok=false on not-found / non-session entries. Mirrors the inline load in
// handlePamConnect so both paths agree on scoping and shape.
func (s *Service) loadPamLaunchEntry(c *gin.Context, orgID, entryID string) (pamLaunchEntry, PamEntryType, bool) {
	ctx := c.Request.Context()
	row := s.db.Pool.QueryRow(ctx, `
		SELECT id, name, entry_type, COALESCE(hostname,''), COALESCE(port,0),
		       COALESCE(username,''), COALESCE(domain,''), COALESCE(url,''), settings,
		       COALESCE(vault_secret_id::text,''), COALESCE(credential_entry_id::text,''),
		       COALESCE(guacamole_connection_id,''), require_approval, record_session,
		       reach_mode, COALESCE(ziti_intercept_port,0)
		  FROM pam_entries WHERE id = $1 AND org_id = $2`, entryID, orgID)

	var entry pamLaunchEntry
	var settingsJSON []byte
	if err := row.Scan(
		&entry.ID, &entry.Name, &entry.EntryType, &entry.Hostname, &entry.Port,
		&entry.Username, &entry.Domain, &entry.URL, &settingsJSON,
		&entry.VaultSecretID, &entry.CredentialEntryID,
		&entry.GuacConnectionID, &entry.RequireApproval, &entry.RecordSession,
		&entry.ReachMode, &entry.ZitiInterceptPort,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "entry not found"})
		} else {
			s.logger.Error("loadPamLaunchEntry: lookup failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load entry"})
		}
		return entry, PamEntryType{}, false
	}
	entry.Settings = decodePamSettings(settingsJSON)

	typeInfo, typeOK := pamEntryTypeByName[entry.EntryType]
	if !typeOK || typeInfo.Kind != "session" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entry is not a launchable session"})
		return entry, PamEntryType{}, false
	}
	return entry, typeInfo, true
}
