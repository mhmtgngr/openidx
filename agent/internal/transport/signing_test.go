package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recordingSigner signs with a real key over a simple message, so a test can
// check the transport passed the method, path and body it actually sent.
type recordingSigner struct {
	priv               *ecdsa.PrivateKey
	method, path, body string
}

func newRecordingSigner(t *testing.T) *recordingSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &recordingSigner{priv: priv}
}

func (s *recordingSigner) SignRequest(method, path string, body []byte) (string, string, error) {
	s.method, s.path, s.body = method, path, string(body)
	d := sha256.Sum256(append([]byte(method+" "+path+" "), body...))
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, d[:])
	return "1759665600", base64.StdEncoding.EncodeToString(sig), err
}

func (s *recordingSigner) verifies(t *testing.T, method, path string, body []byte, sigB64 string) bool {
	t.Helper()
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	d := sha256.Sum256(append([]byte(method+" "+path+" "), body...))
	return ecdsa.VerifyASN1(&s.priv.PublicKey, d[:], sig)
}

func TestAReportIsSignedWhenASignerIsInstalled(t *testing.T) {
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", "agent-1")
	if err := c.ReportResults([]byte(`{"results":[]}`)); err != nil {
		t.Fatal(err)
	}
	if got.Get(headerKeySignature) != "" || got.Get(headerKeyTimestamp) != "" {
		t.Fatal("a client without a signer must send no signature")
	}

	s := newRecordingSigner(t)
	if !SetSigner(c, s) {
		t.Fatal("the HTTPS client takes a signer")
	}
	if err := c.ReportResults([]byte(`{"results":[1]}`)); err != nil {
		t.Fatal(err)
	}
	if got.Get(headerKeyTimestamp) != "1759665600" {
		t.Fatalf("timestamp header %q", got.Get(headerKeyTimestamp))
	}
	if !s.verifies(t, http.MethodPost, "/api/v1/access/agent/report", body, got.Get(headerKeySignature)) {
		t.Fatal("the signature does not cover the method, path and body the server received")
	}
}

func TestEnrollSendsTheDeviceKeyWhenThereIsOne(t *testing.T) {
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&sent)
		_, _ = w.Write([]byte(`{"agent_id":"a","device_id":"d","auth_token":"t","device_key_bound":true}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "", "")
	resp, err := c.Enroll("enroll-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sent["device_key"]; ok {
		t.Fatal("no key was set, so none may be sent")
	}
	c.SetEnrollmentDeviceKey("BASE64KEY", "tpm")
	if resp, err = c.Enroll("enroll-token"); err != nil {
		t.Fatal(err)
	}
	dk, ok := sent["device_key"].(map[string]any)
	if !ok || dk["public_key"] != "BASE64KEY" || dk["kind"] != "tpm" {
		t.Fatalf("device_key sent: %#v", sent["device_key"])
	}
	if !resp.DeviceKeyBound {
		t.Fatal("device_key_bound from the server is read")
	}
}

func TestRegisterDeviceKey(t *testing.T) {
	status := http.StatusCreated
	var body []byte
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/access/agent/device-key" {
			http.NotFound(w, r)
			return
		}
		hdr = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok", "agent-1")
	s := newRecordingSigner(t)

	if err := c.RegisterDeviceKey("BASE64KEY", "software", s); err != nil {
		t.Fatalf("201: %v", err)
	}
	if hdr.Get("X-Agent-ID") != "agent-1" || hdr.Get("Authorization") != "Bearer tok" {
		t.Fatal("the registration is authenticated with the agent credential")
	}
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil || got["public_key"] != "BASE64KEY" || got["kind"] != "software" {
		t.Fatalf("body %s", body)
	}
	if !s.verifies(t, http.MethodPost, "/api/v1/access/agent/device-key", body, hdr.Get(headerKeySignature)) {
		t.Fatal("the registration is signed by the key it registers")
	}
	for code, want := range map[int]error{
		http.StatusNotFound:  ErrDeviceKeyUnsupported,
		http.StatusConflict:  ErrDeviceKeyConflict,
		http.StatusForbidden: ErrAgentRevoked,
	} {
		status = code
		if err := c.RegisterDeviceKey("BASE64KEY", "software", s); !errors.Is(err, want) {
			t.Fatalf("%d: got %v, want %v", code, err, want)
		}
	}
	if err := c.RegisterDeviceKey("BASE64KEY", "software", nil); err == nil {
		t.Fatal("a registration without the key to sign it is refused locally")
	}
}

// A device enrolling again, with a key it already holds, signs the enrolment
// as the agent it was: the server takes that agent's row only on this proof.
// A first enrolment (no agent id yet) sends no signature even with a signer.
func TestAReenrolmentIsSignedAsTheAgentTheDeviceAlreadyIs(t *testing.T) {
	type seen struct {
		agentID, ts, sig string
		body             []byte
	}
	var got seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.agentID = r.Header.Get("X-Agent-ID")
		got.ts = r.Header.Get(headerKeyTimestamp)
		got.sig = r.Header.Get(headerKeySignature)
		got.body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"agent_id":"agent-old","device_id":"device-old","auth_token":"tok"}`))
	}))
	defer srv.Close()

	signer := newRecordingSigner(t)
	c := NewClient(srv.URL, "", "agent-old")
	c.SetSigner(signer)
	if _, err := c.Enroll("enroll-token"); err != nil {
		t.Fatal(err)
	}
	if got.agentID != "agent-old" {
		t.Fatalf("the re-enrolment named %q as the agent, want agent-old", got.agentID)
	}
	if got.ts == "" || got.sig == "" {
		t.Fatal("the re-enrolment carries no signature")
	}
	if signer.path != "/api/v1/access/agent/enroll" || signer.method != http.MethodPost {
		t.Errorf("signed %s %s, want POST /api/v1/access/agent/enroll", signer.method, signer.path)
	}
	if !signer.verifies(t, http.MethodPost, "/api/v1/access/agent/enroll", got.body, got.sig) {
		t.Error("the signature does not verify over the bytes the server received")
	}

	got = seen{}
	first := NewClient(srv.URL, "", "")
	first.SetSigner(signer)
	if _, err := first.Enroll("enroll-token"); err != nil {
		t.Fatal(err)
	}
	if got.agentID != "" || got.sig != "" {
		t.Errorf("a first enrolment signed as %q (signature %q); it has no agent to sign as", got.agentID, got.sig)
	}
}
