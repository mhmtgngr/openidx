// Package desktoppam drives the end-user PAM experience from the desktop:
// list the caller's connections and launch a brokered session (open the
// Guacamole connect URL in the browser). Mirrors the mobile features/pam.
package desktoppam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
var ErrApprovalRequired = errors.New("this connection requires an approved access request")

// ErrStepUpRequired indicates the session's last verified second factor is
// older than the server allows for a privileged launch (STEPUP_GATE). The
// person has to verify a factor again; no approval would help.
var ErrStepUpRequired = errors.New("this connection needs a recently verified second factor")

// ErrNotSignedIn indicates the access token was refused outright (401): the
// session is over, and the person has to sign in again.
var ErrNotSignedIn = errors.New("the session has expired; sign in again")

// Refusal is a non-2xx answer from the server, with whatever it said about
// why, so a caller can tell the person at the device what to do rather than
// "status 403". Every 403 used to be reported as ErrApprovalRequired, which
// sent a user whose second factor had merely gone stale to ask an approver.
type Refusal struct {
	Status int
	// Code is the machine-readable reason: the body's "code" when the server
	// sends one, else its "error" field (which carries step_up_required and
	// the like).
	Code string
	// Detail is the human-readable reason, when the body carries one apart
	// from the code.
	Detail string
	// ApprovalRequired is the server's explicit flag that an access request
	// would unlock the entry.
	ApprovalRequired bool
}

func (r *Refusal) Error() string {
	switch {
	case r.Detail != "" && r.Code != "":
		return fmt.Sprintf("the server refused the request (%d %s): %s", r.Status, r.Code, r.Detail)
	case r.Code != "":
		return fmt.Sprintf("the server refused the request (%d %s)", r.Status, r.Code)
	case r.Detail != "":
		return fmt.Sprintf("the server refused the request (%d): %s", r.Status, r.Detail)
	}
	return fmt.Sprintf("the server refused the request (%d)", r.Status)
}

// maxErrorBody bounds how much of an error answer is read for its reason.
const maxErrorBody = 64 << 10

// refusalFrom reads an error answer's body into a Refusal. A body that is not
// JSON, or is empty, yields a Refusal with the status alone.
func refusalFrom(status int, body io.Reader) *Refusal {
	r := &Refusal{Status: status}
	raw, _ := io.ReadAll(io.LimitReader(body, maxErrorBody))
	var b struct {
		Error            string `json:"error"`
		Code             string `json:"code"`
		Description      string `json:"error_description"`
		Message          string `json:"message"`
		ApprovalRequired bool   `json:"approval_required"`
	}
	if json.Unmarshal(raw, &b) != nil {
		return r
	}
	r.Code = b.Code
	if r.Code == "" {
		r.Code = b.Error
	}
	r.Detail = b.Description
	if r.Detail == "" {
		r.Detail = b.Message
	}
	if r.Detail == "" && b.Code != "" {
		// With a separate code, the "error" field is the human reason.
		r.Detail = b.Error
	}
	r.ApprovalRequired = b.ApprovalRequired ||
		strings.Contains(strings.ToLower(b.Error), "requires approval")
	return r
}

// classify wraps a Refusal in the sentinel a caller can act on, when there is
// one. Any other refusal is returned as it is, reason and all.
func classify(err error) error {
	var ref *Refusal
	if !errors.As(err, &ref) {
		return err
	}
	switch {
	case ref.Status == http.StatusUnauthorized:
		return fmt.Errorf("%w: %w", ErrNotSignedIn, ref)
	case ref.Status == http.StatusForbidden && ref.Code == "step_up_required":
		return fmt.Errorf("%w: %w", ErrStepUpRequired, ref)
	case ref.Status == http.StatusForbidden && ref.ApprovalRequired:
		return fmt.Errorf("%w: %w", ErrApprovalRequired, ref)
	}
	return err
}

// UserMessage is the one-line explanation the tray shows for a failed
// connect: what happened and what the person can do about it.
func UserMessage(err error) string {
	var ref *Refusal
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrStepUpRequired):
		return "This connection needs a recently verified second factor. Sign out, sign in again, and retry."
	case errors.Is(err, ErrApprovalRequired):
		return "This connection needs an approved access request. Ask your administrator, or file a request in the OpenIDX portal."
	case errors.Is(err, ErrNotSignedIn):
		return "Your session has expired. Sign in again."
	case errors.As(err, &ref):
		switch {
		case ref.Detail != "":
			return "The server refused the connection: " + ref.Detail
		case ref.Code != "":
			return "The server refused the connection: " + ref.Code
		}
		return fmt.Sprintf("The server refused the connection (HTTP %d).", ref.Status)
	}
	return "Could not start the connection: " + err.Error()
}

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
// Returns the ConnectResult. A refusal comes back typed: ErrApprovalRequired,
// ErrStepUpRequired or ErrNotSignedIn when the server's answer says which,
// else a *Refusal carrying the server's own reason.
func Connect(ctx context.Context, serverURL, token, entryID string) (*ConnectResult, error) {
	var res ConnectResult
	err := doJSON(ctx, http.MethodPost,
		serverURL+"/api/v1/access/pam/entries/"+entryID+"/connect", token, []byte("{}"), &res)
	if err != nil {
		return nil, classify(err)
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
		return fmt.Errorf("%s %s: %w", method, url, refusalFrom(resp.StatusCode, resp.Body))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
