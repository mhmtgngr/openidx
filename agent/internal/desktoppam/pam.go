// Package desktoppam drives the end-user PAM experience from the desktop:
// list the caller's connections and launch a brokered session (open the
// Guacamole connect URL in the browser). Mirrors the mobile features/pam.
package desktoppam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/openidx/openidx/agent/internal/sso"
)

// Entry is a launchable PAM connection.
type Entry struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	EntryType       string `json:"entry_type"`
	RequireApproval bool   `json:"require_approval"`
	RecordSession   bool   `json:"record_session"`
	ReachMode       string `json:"reach_mode,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	Port            int    `json:"port,omitempty"`
}

// ConnectResult is the launch payload from the connect endpoint.
type ConnectResult struct {
	LaunchType string `json:"launch_type"`
	ConnectURL string `json:"connect_url,omitempty"`
	URL        string `json:"url,omitempty"`
	EntryID    string `json:"entry_id"`
	SessionID  string `json:"session_id,omitempty"`
	ReachMode  string `json:"reach_mode,omitempty"`
}

// ErrApprovalRequired indicates the entry needs an approved access request.
var ErrApprovalRequired = fmt.Errorf("this connection requires an approved access request")

// ListEntries returns the caller's launchable PAM connections.
func ListEntries(ctx context.Context, serverURL, token string) ([]Entry, error) {
	var out struct {
		Entries []Entry `json:"entries"`
	}
	if err := doJSON(ctx, http.MethodGet, serverURL+"/api/v1/access/pam/entries", token, nil, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

// Connect launches a session for the entry and opens it in the browser.
// Returns the ConnectResult; on 403 returns ErrApprovalRequired.
func Connect(ctx context.Context, serverURL, token, entryID string) (*ConnectResult, error) {
	var res ConnectResult
	err := doJSON(ctx, http.MethodPost,
		serverURL+"/api/v1/access/pam/entries/"+entryID+"/connect", token, []byte("{}"), &res)
	if err != nil {
		if strings.Contains(err.Error(), "status 403") {
			return nil, ErrApprovalRequired
		}
		return nil, err
	}
	target := res.ConnectURL
	if target == "" {
		target = res.URL
	}
	if target != "" {
		_ = sso.OpenURL(target)
	}
	return &res, nil
}

// RequestAccess files an access request for an approval-gated entry.
func RequestAccess(ctx context.Context, serverURL, token, entryID, reason string) error {
	body, _ := json.Marshal(map[string]string{"reason": reason})
	return doJSON(ctx, http.MethodPost,
		serverURL+"/api/v1/access/pam/entries/"+entryID+"/request", token, body, nil)
}

func doJSON(ctx context.Context, method, url, token string, body []byte, out interface{}) error {
	var r *http.Request
	var err error
	if body != nil {
		r, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	} else {
		r, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: status %d", method, url, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
