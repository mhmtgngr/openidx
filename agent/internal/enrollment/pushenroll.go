package enrollment

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// pushEnrollRequest is the body posted to the identity-service public push
// enroll-complete endpoint. It mirrors identity.PushMFAEnrollment plus the
// single-use enrollment_token that authorizes the bind.
type pushEnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	DeviceToken     string `json:"device_token"`
	Platform        string `json:"platform"`
	DeviceName      string `json:"device_name,omitempty"`
	DeviceModel     string `json:"device_model,omitempty"`
	OSVersion       string `json:"os_version,omitempty"`
	AppVersion      string `json:"app_version,omitempty"`
}

// CompletePushEnroll redeems a push-MFA enrollment ticket (FastPass): it POSTs
// the device's push token to the server's push enroll-complete path, binding
// this phone as an approver for the enrolling user — no separate MFA setup.
//
// serverURL is the base origin (e.g. https://openidx.tdv.org); path is the
// server-advertised push_enroll_path. Returns an error on any non-2xx so the
// caller can surface it; the caller decides whether to treat failure as fatal
// (it should not — enrollment already succeeded).
func CompletePushEnroll(serverURL, path, ticket, deviceToken, platform, deviceName string, insecureSkipVerify bool) error {
	if strings.TrimSpace(ticket) == "" || strings.TrimSpace(path) == "" {
		return fmt.Errorf("no pending push enrollment ticket")
	}
	if strings.TrimSpace(deviceToken) == "" {
		return fmt.Errorf("device push token is required")
	}
	if platform != "ios" && platform != "android" && platform != "web" {
		return fmt.Errorf("invalid platform %q (must be ios, android, or web)", platform)
	}

	body, err := json.Marshal(pushEnrollRequest{
		EnrollmentToken: ticket,
		DeviceToken:     deviceToken,
		Platform:        platform,
		DeviceName:      deviceName,
	})
	if err != nil {
		return err
	}

	url := strings.TrimRight(serverURL, "/") + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	if insecureSkipVerify {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // dev/self-signed opt-in, mirrors agent HTTP posture
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push enroll request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("push enroll rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}
