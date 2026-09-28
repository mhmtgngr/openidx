package access

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openidx/openidx/internal/common/resilience"
	"github.com/openidx/openidx/internal/common/secretcrypt"
	"go.uber.org/zap"
)

// The Guacamole connection password is the only secret a FeatureConfig carries,
// and sealing it at rest is why this release put it there. Every caller of
// EnableFeature logs the error it returns -- five of them as zap.Error(err) --
// and feature_handlers.go also hands err.Error() back to the API client, so an
// error that quoted the password would publish it to the log and to the caller
// at once.
//
// CodeQL reads the struct rather than the messages: because the type now names
// a password, every error out of a function that takes the config is treated as
// carrying it, and those five log lines are reported as go/clear-text-logging
// at 7.5. docs/evidence/codeql-triage.md records the verdict; these two tests
// are what make it checkable instead of a claim, and they cover the two places
// the password is read -- the seal on the way to storage, and the connection
// parameters on the way to the broker.

func TestSealingAFeatureConfigKeepsThePasswordOutOfItsJSONAndItsErrors(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"
	const password = "guacamole-connection-secret"

	cipher, err := secretcrypt.New(key)
	if err != nil {
		t.Fatalf("secretcrypt.New: %v", err)
	}
	fm := &FeatureManager{cipher: cipher}

	stored, err := fm.storedConfigJSON(&FeatureConfig{
		GuacamoleProtocol: "rdp", GuacamoleHost: "10.0.0.1", GuacamolePort: 3389,
		GuacamoleUsername: "operator", GuacamolePassword: password,
	})
	if err != nil {
		t.Fatalf("storedConfigJSON: %v", err)
	}
	if strings.Contains(string(stored), password) {
		t.Fatalf("the stored config carries the password in the clear: %s", stored)
	}

	// Openable again, or the assertion above would also pass on a config that
	// had simply dropped the password on the way to the table.
	var back FeatureConfig
	if err := json.Unmarshal(stored, &back); err != nil {
		t.Fatalf("unmarshal stored config: %v", err)
	}
	opened, err := fm.openSecret(back.GuacamolePassword)
	if err != nil {
		t.Fatalf("openSecret on a value this cipher sealed: %v", err)
	}
	if opened != password {
		t.Fatalf("the sealed value opened as %q, want the password back", opened)
	}

	// The refusal an operator meets when ENCRYPTION_KEY does not match the
	// data names the key, never the value -- neither the password nor the
	// ciphertext standing in for it.
	other, err := secretcrypt.New("fedcba9876543210fedcba9876543210")
	if err != nil {
		t.Fatalf("secretcrypt.New (other key): %v", err)
	}
	_, err = (&FeatureManager{cipher: other}).openSecret(back.GuacamolePassword)
	if err == nil {
		t.Fatal("opening a value sealed under another key must fail")
	}
	if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), back.GuacamolePassword) {
		t.Fatalf("the refusal quotes the secret: %v", err)
	}
}

// A broker that refuses the create answers 4xx with a body, and that body is
// quoted into the error the five log lines write. Guacamole answers with its
// own message object, so the quote carries a reason and not a credential.
//
// The limit of this test, stated rather than hidden: it pins what the error
// does with what the broker SENDS. A broker that echoed the request back would
// put the password in that body, and the quote would carry it. The broker is
// operator-configured and already holds the password, and Guacamole's REST API
// answers with a message rather than the request, so that is a note for the
// follow-up list, not a defect this branch introduces.
func TestABrokerRefusalNeverQuotesTheConnectionPassword(t *testing.T) {
	const password = "guacamole-connection-secret"

	var sent map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &sent)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"Connection names must be unique.","type":"BAD_REQUEST"}`))
	}))
	defer srv.Close()

	gc := &GuacamoleClient{
		baseURL:    srv.URL,
		dataSource: "postgresql",
		authToken:  "test-token",
		httpClient: resilience.NewResilientHTTPClient(srv.Client(), guacBreaker("test", zap.NewNop())),
		logger:     zap.NewNop(),
	}

	_, err := gc.CreateConnection("pam-x", "rdp", "10.0.0.1", 3389,
		map[string]string{"username": "operator", "password": password})
	if err == nil {
		t.Fatal("a refused create must be an error")
	}

	// The password really did travel to the broker, so the assertion below is
	// about the error rather than about an argument nothing read.
	params, _ := sent["parameters"].(map[string]interface{})
	if params["password"] != password {
		t.Fatalf("the request did not carry the password, so this test proves nothing: %#v", sent)
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("the broker refusal quotes the connection password: %v", err)
	}
	// It does carry the reason; an error that named neither would be no use to
	// the operator reading the log line.
	if !strings.Contains(err.Error(), "must be unique") {
		t.Errorf("the error drops the broker's reason: %v", err)
	}
}
