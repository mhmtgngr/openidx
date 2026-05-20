package access

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// canonicalResponse builds a decodeIntegrityToken JSON response with the
// supplied invariants. Time-based fields default to "now" so callers don't
// need to thread timestamps through every test.
func canonicalResponse(pkg string, appVerdict string, deviceLabels []string) string {
	labels := ""
	for i, l := range deviceLabels {
		if i > 0 {
			labels += ","
		}
		labels += "\"" + l + "\""
	}
	return `{
        "tokenPayloadExternal": {
            "requestDetails": {
                "requestPackageName": "` + pkg + `",
                "nonce": "abc123",
                "timestampMillis": "` + millis(time.Now()) + `"
            },
            "appIntegrity": {
                "appRecognitionVerdict": "` + appVerdict + `",
                "packageName": "` + pkg + `",
                "versionCode": "1"
            },
            "deviceIntegrity": {
                "deviceRecognitionVerdict": [` + labels + `]
            },
            "accountDetails": {
                "appLicensingVerdict": "LICENSED"
            }
        }
    }`
}

func millis(t time.Time) string {
	v := t.UnixMilli()
	// Format without external deps — testing only.
	out := ""
	if v == 0 {
		return "0"
	}
	for v > 0 {
		out = string(rune('0'+(v%10))) + out
		v /= 10
	}
	return out
}

func TestPlayIntegrityVerifier_parseAndValidate_PackageMismatch(t *testing.T) {
	v := &PlayIntegrityVerifier{packageName: "com.openidx.agent", maxTokenAge: time.Hour}
	_, err := v.parseAndValidate([]byte(canonicalResponse("com.attacker.app", "PLAY_RECOGNIZED", []string{"MEETS_DEVICE_INTEGRITY"})))
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "package mismatch")
}

func TestPlayIntegrityVerifier_parseAndValidate_TokenTooOld(t *testing.T) {
	v := &PlayIntegrityVerifier{packageName: "com.openidx.agent", maxTokenAge: 1 * time.Second}
	staleResp := canonicalResponse("com.openidx.agent", "PLAY_RECOGNIZED", []string{"MEETS_DEVICE_INTEGRITY"})
	// Replace the "now" timestamp with one 10 minutes ago.
	staleResp = strings.Replace(staleResp,
		"\"timestampMillis\": \""+millis(time.Now())+"\"",
		"\"timestampMillis\": \""+millis(time.Now().Add(-10*time.Minute))+"\"",
		1)
	_, err := v.parseAndValidate([]byte(staleResp))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestPlayIntegrityVerifier_parseAndValidate_HappyPath(t *testing.T) {
	v := &PlayIntegrityVerifier{packageName: "com.openidx.agent", maxTokenAge: time.Hour}
	resp := canonicalResponse("com.openidx.agent", "PLAY_RECOGNIZED",
		[]string{"MEETS_DEVICE_INTEGRITY", "MEETS_BASIC_INTEGRITY"})
	verdict, err := v.parseAndValidate([]byte(resp))
	require.NoError(t, err)
	assert.Equal(t, "com.openidx.agent", verdict.PackageName)
	assert.Equal(t, "abc123", verdict.Nonce)
	assert.Equal(t, "PLAY_RECOGNIZED", verdict.AppRecognitionVerdict)
	assert.Contains(t, verdict.DeviceRecognitionVerdict, "MEETS_DEVICE_INTEGRITY")
	assert.Contains(t, verdict.DeviceRecognitionVerdict, "MEETS_BASIC_INTEGRITY")
}

func TestIntegrityPolicy_Pass_AllSatisfied(t *testing.T) {
	p := IntegrityPolicy{
		RequireMeetsDeviceIntegrity: true,
		RequireMeetsBasicIntegrity:  true,
		RequirePlayRecognized:       true,
	}
	v := IntegrityVerdict{
		AppRecognitionVerdict:    "PLAY_RECOGNIZED",
		DeviceRecognitionVerdict: []string{"MEETS_DEVICE_INTEGRITY", "MEETS_BASIC_INTEGRITY"},
	}
	assert.True(t, p.Pass(v))
}

func TestIntegrityPolicy_Pass_MissingDeviceIntegrity(t *testing.T) {
	p := IntegrityPolicy{RequireMeetsDeviceIntegrity: true}
	v := IntegrityVerdict{DeviceRecognitionVerdict: []string{"MEETS_BASIC_INTEGRITY"}}
	assert.False(t, p.Pass(v))
}

func TestIntegrityPolicy_Pass_NotPlayRecognized(t *testing.T) {
	p := IntegrityPolicy{RequirePlayRecognized: true}
	v := IntegrityVerdict{AppRecognitionVerdict: "UNRECOGNIZED_VERSION"}
	assert.False(t, p.Pass(v))
}

func TestIntegrityPolicy_Pass_EmptyPolicyTrivially(t *testing.T) {
	p := IntegrityPolicy{}
	v := IntegrityVerdict{}
	assert.True(t, p.Pass(v), "an unconfigured policy must pass everything")
}

func TestPlayIntegrityVerifier_Enabled(t *testing.T) {
	var nilVerifier *PlayIntegrityVerifier
	assert.False(t, nilVerifier.Enabled())

	emptyVerifier := &PlayIntegrityVerifier{}
	assert.False(t, emptyVerifier.Enabled())
}

func TestNewPlayIntegrityVerifier_BothEmpty_ReturnsNil(t *testing.T) {
	v, err := NewPlayIntegrityVerifier(t.Context(), nil, nil, "")
	require.NoError(t, err)
	assert.Nil(t, v, "construction with no inputs is a soft disable, not an error")
}

func TestNewPlayIntegrityVerifier_RequiresBothInputs(t *testing.T) {
	_, err := NewPlayIntegrityVerifier(t.Context(), nil, []byte("{}"), "")
	require.Error(t, err)
	_, err = NewPlayIntegrityVerifier(t.Context(), nil, nil, "com.openidx.agent")
	require.Error(t, err)
}
