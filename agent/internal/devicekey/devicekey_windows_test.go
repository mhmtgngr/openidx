//go:build windows

package devicekey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"
)

// TestNCryptSoftwareKeyRoundTrip creates a per-user key in the software key
// storage provider (a test cannot assume the runner is elevated or has a
// TPM), signs with it, verifies the signature in Go, finds it again by name,
// and deletes it.
func TestNCryptSoftwareKeyRoundTrip(t *testing.T) {
	name := fmt.Sprintf("OpenIDX Agent Test Key %d", time.Now().UnixNano())
	k, err := createIn(providerSoftware, KindSoftware, name, 0)
	if err != nil {
		t.Fatalf("create in the software provider: %v", err)
	}
	t.Cleanup(func() {
		k.Close()
		if err := deleteNamed(name, 0); err != nil {
			t.Errorf("delete the test key: %v", err)
		}
	})
	d := sha256.Sum256([]byte("openidx"))
	sig, err := k.Sign(d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(k.Public(), d[:], sig) {
		t.Fatal("the provider's signature does not verify in Go")
	}
	found, err := openNamed(name, 0)
	if err != nil {
		t.Fatalf("open by name: %v", err)
	}
	defer found.Close()
	if found.Kind() != KindSoftware || !found.Public().Equal(k.Public()) {
		t.Fatalf("found %s key, want the software key just made", found.Kind())
	}
}

// TestNCryptTPMKeyWhenPresent does the same in the Platform Crypto Provider
// when the runner has a TPM, and says so when it does not.
func TestNCryptTPMKeyWhenPresent(t *testing.T) {
	name := fmt.Sprintf("OpenIDX Agent Test TPM Key %d", time.Now().UnixNano())
	k, err := createIn(providerPlatform, KindTPM, name, 0)
	if err != nil {
		t.Skipf("no usable TPM on this runner: %v", err)
	}
	t.Cleanup(func() {
		k.Close()
		_ = deleteNamed(name, 0)
	})
	d := sha256.Sum256([]byte("openidx"))
	sig, err := k.Sign(d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.VerifyASN1(k.Public(), d[:], sig) {
		t.Fatal("the TPM's signature does not verify in Go")
	}
}
