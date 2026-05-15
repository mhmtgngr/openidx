// Package access — server-side Play Integrity token verification.
//
// The Android agent obtains a Play Integrity token via the Play Integrity
// API and forwards it raw inside the posture-check result for
// `play_integrity`. Without server-side verification the token is just
// opaque bytes; this file calls Google's decodeIntegrityToken API,
// extracts the verdict, and decides pass/fail based on the policy
// recorded in posture_checks.parameters.
//
// Verifier is optional. When the service account isn't configured the
// agent's report is persisted unchanged with a warning audit so admins
// can see they're trusting the device's own attestation without server
// verification.
package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// IntegrityVerdict is the subset of the Play Integrity response we
// persist and evaluate against policy. The full response carries more
// fields (account licensing, environment details) we may add later.
type IntegrityVerdict struct {
	// PackageName from RequestDetails — must match the configured expected
	// package or the verdict is rejected.
	PackageName string `json:"package_name"`
	// Nonce echoed back by Google; we expose it so the policy layer (or
	// future replay detection) can compare against the issued nonce.
	Nonce string `json:"nonce"`
	// RequestTimestampMillis when Google signed the token.
	RequestTimestampMillis int64 `json:"request_timestamp_ms"`

	// App integrity verdict: one of PLAY_RECOGNIZED, UNRECOGNIZED_VERSION,
	// UNEVALUATED.
	AppRecognitionVerdict string `json:"app_recognition_verdict"`

	// Device integrity labels — zero or more of:
	//   MEETS_DEVICE_INTEGRITY
	//   MEETS_BASIC_INTEGRITY
	//   MEETS_STRONG_INTEGRITY
	//   MEETS_VIRTUAL_INTEGRITY
	DeviceRecognitionVerdict []string `json:"device_recognition_verdict"`

	// Account licensing: LICENSED, UNLICENSED, UNEVALUATED.
	AccountActivity string `json:"account_activity,omitempty"`
}

// IntegrityPolicy describes what the server expects of the verdict for
// the result to count as a pass. Parsed from posture_checks.parameters.
type IntegrityPolicy struct {
	RequireMeetsDeviceIntegrity bool `json:"require_meets_device_integrity"`
	RequireMeetsBasicIntegrity  bool `json:"require_meets_basic_integrity"`
	RequireMeetsStrongIntegrity bool `json:"require_meets_strong_integrity"`
	RequirePlayRecognized       bool `json:"require_play_recognized"`
}

// Pass returns true iff the supplied verdict satisfies every "Require*"
// flag set on this policy. An empty policy passes trivially — the
// server-side check still records the verdict so admins can see it.
func (p IntegrityPolicy) Pass(v IntegrityVerdict) bool {
	hasLabel := func(label string) bool {
		for _, l := range v.DeviceRecognitionVerdict {
			if strings.EqualFold(l, label) {
				return true
			}
		}
		return false
	}
	if p.RequireMeetsDeviceIntegrity && !hasLabel("MEETS_DEVICE_INTEGRITY") {
		return false
	}
	if p.RequireMeetsBasicIntegrity && !hasLabel("MEETS_BASIC_INTEGRITY") {
		return false
	}
	if p.RequireMeetsStrongIntegrity && !hasLabel("MEETS_STRONG_INTEGRITY") {
		return false
	}
	if p.RequirePlayRecognized && !strings.EqualFold(v.AppRecognitionVerdict, "PLAY_RECOGNIZED") {
		return false
	}
	return true
}

// PlayIntegrityVerifier verifies Play Integrity tokens by calling Google's
// decodeIntegrityToken API. Construct via NewPlayIntegrityVerifier. The
// zero value is safe but unusable — callers must check Enabled().
type PlayIntegrityVerifier struct {
	logger          *zap.Logger
	tokenSource     oauth2.TokenSource
	httpClient      *http.Client
	packageName     string
	maxTokenAge     time.Duration
	allowedClockSkew time.Duration
}

// Enabled reports whether the verifier is wired with credentials. When
// false, callers should skip verification and just persist the raw token.
func (v *PlayIntegrityVerifier) Enabled() bool {
	return v != nil && v.tokenSource != nil && v.packageName != ""
}

// NewPlayIntegrityVerifier parses the supplied service-account JSON and
// returns a verifier configured to call decodeIntegrityToken for
// `packageName`. Returns (nil, nil) when both inputs are empty so callers
// can construct unconditionally in dev mode.
func NewPlayIntegrityVerifier(
	ctx context.Context,
	logger *zap.Logger,
	serviceAccountJSON []byte,
	packageName string,
) (*PlayIntegrityVerifier, error) {
	if len(serviceAccountJSON) == 0 && packageName == "" {
		return nil, nil
	}
	if len(serviceAccountJSON) == 0 || packageName == "" {
		return nil, errors.New("play integrity verifier requires both service-account JSON and package name")
	}
	creds, err := google.CredentialsFromJSON(ctx, serviceAccountJSON, integrityScope)
	if err != nil {
		return nil, fmt.Errorf("parse service account: %w", err)
	}
	return &PlayIntegrityVerifier{
		logger:           logger,
		tokenSource:      creds.TokenSource,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
		packageName:      packageName,
		maxTokenAge:      10 * time.Minute,
		allowedClockSkew: 30 * time.Second,
	}, nil
}

// Verify exchanges a Play Integrity token for the decoded verdict and
// validates basic invariants (package name match, freshness). Returns a
// structured verdict on success or an error describing why the token
// can't be trusted.
func (v *PlayIntegrityVerifier) Verify(ctx context.Context, token string) (IntegrityVerdict, error) {
	if !v.Enabled() {
		return IntegrityVerdict{}, errors.New("verifier not configured")
	}
	if strings.TrimSpace(token) == "" {
		return IntegrityVerdict{}, errors.New("empty integrity token")
	}

	body, _ := json.Marshal(map[string]string{"integrity_token": token})
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf(
		"https://playintegrity.googleapis.com/v1/%s:decodeIntegrityToken",
		v.packageName,
	)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return IntegrityVerdict{}, fmt.Errorf("build request: %w", err)
	}
	tok, err := v.tokenSource.Token()
	if err != nil {
		return IntegrityVerdict{}, fmt.Errorf("get access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return IntegrityVerdict{}, fmt.Errorf("call decodeIntegrityToken: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return IntegrityVerdict{}, fmt.Errorf("decodeIntegrityToken %d: %s", resp.StatusCode, string(respBody))
	}
	return v.parseAndValidate(respBody)
}

// parseAndValidate decodes the Google response and enforces the basic
// invariants every caller cares about (package name, token freshness).
// Separated out so tests can feed canned responses without going through
// the HTTP layer.
func (v *PlayIntegrityVerifier) parseAndValidate(respBody []byte) (IntegrityVerdict, error) {
	var raw decodeIntegrityTokenResponse
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return IntegrityVerdict{}, fmt.Errorf("parse response: %w", err)
	}
	tp := raw.TokenPayloadExternal
	verdict := IntegrityVerdict{
		PackageName:              tp.RequestDetails.RequestPackageName,
		Nonce:                    tp.RequestDetails.Nonce,
		RequestTimestampMillis:   tp.RequestDetails.TimestampMillis,
		AppRecognitionVerdict:    tp.AppIntegrity.AppRecognitionVerdict,
		DeviceRecognitionVerdict: tp.DeviceIntegrity.DeviceRecognitionVerdict,
		AccountActivity:          tp.AccountDetails.AppLicensingVerdict,
	}
	if verdict.PackageName != v.packageName {
		return verdict, fmt.Errorf("integrity token package mismatch: got %q want %q",
			verdict.PackageName, v.packageName)
	}
	if v.maxTokenAge > 0 {
		issued := time.UnixMilli(verdict.RequestTimestampMillis)
		age := time.Since(issued)
		if age > v.maxTokenAge+v.allowedClockSkew {
			return verdict, fmt.Errorf("integrity token too old: %s", age)
		}
		if age < -v.allowedClockSkew {
			return verdict, fmt.Errorf("integrity token from the future: %s", -age)
		}
	}
	return verdict, nil
}

// integrityScope is the OAuth scope Google requires for the Play
// Integrity API. Documented at
// https://developers.google.com/android/play/integrity/standard.
const integrityScope = "https://www.googleapis.com/auth/playintegrity"

// decodeIntegrityTokenResponse mirrors the JSON shape Google returns.
// Field names match the public API verbatim — keep them in sync if
// Google adds new sub-objects.
type decodeIntegrityTokenResponse struct {
	TokenPayloadExternal struct {
		RequestDetails struct {
			RequestPackageName string `json:"requestPackageName"`
			Nonce              string `json:"nonce"`
			TimestampMillis    int64  `json:"timestampMillis,string"`
		} `json:"requestDetails"`
		AppIntegrity struct {
			AppRecognitionVerdict string `json:"appRecognitionVerdict"`
			PackageName           string `json:"packageName"`
			CertificateSha256     []string `json:"certificateSha256Digest"`
			VersionCode           string `json:"versionCode"`
		} `json:"appIntegrity"`
		DeviceIntegrity struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		} `json:"deviceIntegrity"`
		AccountDetails struct {
			AppLicensingVerdict string `json:"appLicensingVerdict"`
		} `json:"accountDetails"`
	} `json:"tokenPayloadExternal"`
}
