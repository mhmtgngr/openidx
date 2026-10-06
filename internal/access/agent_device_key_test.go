package access

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"
)

func newTestDeviceKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(der)
}

// signAgentRequest signs as agent/internal/devicekey.Signer does.
func signAgentRequest(t *testing.T, priv *ecdsa.PrivateKey, method, path, agentID string, ts time.Time, body []byte) (string, string) {
	t.Helper()
	in, err := agentRequestSigningInput(method, path, agentID, ts.Unix(), body)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(in)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(ts.Unix(), 10), base64.StdEncoding.EncodeToString(sig)
}

// The agent builds the same bytes (agent/internal/devicekey
// TestRequestSigningInputIsPinned pins the same string), so the two modules
// cannot drift apart without one of the two tests failing.
func TestAgentRequestSigningInputMatchesTheAgent(t *testing.T) {
	got, err := agentRequestSigningInput("POST", "/api/v1/access/agent/report", "agent-1", 1759665600, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(`{"a":1}`))
	want := "openidx-agent-request/v1\nPOST\n/api/v1/access/agent/report\nagent-1\n1759665600\n" +
		hex.EncodeToString(sum[:]) + "\n"
	if string(got) != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if _, err := agentRequestSigningInput("POST", "/p\n/q", "a", 1, nil); err == nil {
		t.Fatal("a line break must be refused")
	}
}

func TestParseDeviceKey(t *testing.T) {
	_, b64 := newTestDeviceKey(t)
	if _, kind, err := parseDeviceKey(deviceKeyRequest{PublicKey: b64, Kind: "tpm"}); err != nil || kind != "tpm" {
		t.Fatalf("a P-256 TPM key: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	for name, req := range map[string]deviceKeyRequest{
		"unknown kind": {PublicKey: b64, Kind: "hsm"},
		"not base64":   {PublicKey: "%%%", Kind: "file"},
		"not PKIX":     {PublicKey: base64.StdEncoding.EncodeToString([]byte("nope")), Kind: "file"},
		"wrong curve":  {PublicKey: base64.StdEncoding.EncodeToString(der384), Kind: "file"},
	} {
		if _, _, err := parseDeviceKey(req); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

func TestVerifyAgentRequestSignature(t *testing.T) {
	priv, _ := newTestDeviceKey(t)
	other, _ := newTestDeviceKey(t)
	now := time.Unix(1759665600, 0)
	body := []byte(`{"results":[]}`)
	const path = "/api/v1/access/agent/report"
	ts, sig := signAgentRequest(t, priv, "POST", path, "agent-1", now, body)

	if err := verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", body, ts, sig, now); err != nil {
		t.Fatalf("a good signature: %v", err)
	}
	if err := verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", body, "", "", now); !errors.Is(err, errDeviceSignatureMissing) {
		t.Fatalf("no signature: %v", err)
	}
	refused := map[string]error{
		"another body":    verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", []byte(`{}`), ts, sig, now),
		"another path":    verifyAgentRequestSignature(&priv.PublicKey, "POST", "/api/v1/access/agent/config", "agent-1", body, ts, sig, now),
		"another agent":   verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-2", body, ts, sig, now),
		"another key":     verifyAgentRequestSignature(&other.PublicKey, "POST", path, "agent-1", body, ts, sig, now),
		"too old":         verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", body, ts, sig, now.Add(6*time.Minute)),
		"from the future": verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", body, ts, sig, now.Add(-6*time.Minute)),
		"not base64":      verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", body, ts, "%%%", now),
		"bad timestamp":   verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", body, "yesterday", sig, now),
	}
	for name, err := range refused {
		if err == nil || errors.Is(err, errDeviceSignatureMissing) {
			t.Fatalf("%s: got %v, want a refusal", name, err)
		}
	}
	if err := verifyAgentRequestSignature(&priv.PublicKey, "POST", path, "agent-1", body, ts, sig, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
}
