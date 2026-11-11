package transport

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
)

// CommandResponder is a Transport that can answer a fleet command
// (POST /agent/commands/:id/result, Faz B8.6).
type CommandResponder interface {
	SendCommandResult(commandID string, data []byte) error
}

// SendCommandResult posts a command's result, signed like a report when the
// device holds a key.
func (c *Client) SendCommandResult(commandID string, data []byte) error {
	u := c.baseURL + "/api/v1/access/agent/commands/" + url.PathEscape(commandID) + "/result"
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating command result request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.agentID)
	if err := sign(req, c.signer, data); err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending command result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("command result: %w", ErrAgentAuthInvalid)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("command result refused with status %d", resp.StatusCode)
	}
	return nil
}

// SendCommandResult delegates over the Ziti-backed HTTP client.
func (c *ZitiClient) SendCommandResult(commandID string, data []byte) error {
	inner := &Client{baseURL: c.baseURL, authToken: c.authToken, agentID: c.agentID, httpClient: c.httpClient,
		signer: c.signer}
	return inner.SendCommandResult(commandID, data)
}

// SendCommandResult answers over the best available path.
func (r *ResilientTransport) SendCommandResult(commandID string, data []byte) error {
	send := func(t Transport) (struct{}, error) {
		cr, ok := t.(CommandResponder)
		if !ok {
			return struct{}{}, fmt.Errorf("transport cannot answer commands")
		}
		return struct{}{}, cr.SendCommandResult(commandID, data)
	}
	_, err := runResilient(r, send, send)
	return err
}

// AcceptCommandsHeader on GET /agent/config tells the server this process
// runs fleet commands, so it may hand them over. The tray, which syncs config
// with the same credential for remote support only, never sends it and so
// never takes a command meant for the service.
const AcceptCommandsHeader = "X-Agent-Accept-Commands"

type commandAccepter interface{ SetAcceptCommands(bool) }

// SetAcceptCommands marks t as the process that runs fleet commands.
func SetAcceptCommands(t Transport, on bool) {
	if a, ok := t.(commandAccepter); ok {
		a.SetAcceptCommands(on)
	}
}

// SetAcceptCommands implements commandAccepter.
func (c *Client) SetAcceptCommands(on bool) { c.acceptCommands = on }

// SetAcceptCommands implements commandAccepter.
func (c *ZitiClient) SetAcceptCommands(on bool) { c.acceptCommands = on }

// SetAcceptCommands implements commandAccepter.
func (r *ResilientTransport) SetAcceptCommands(on bool) {
	SetAcceptCommands(r.ziti, on)
	SetAcceptCommands(r.https, on)
}
