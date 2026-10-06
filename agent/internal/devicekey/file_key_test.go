//go:build !windows

package devicekey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyIsMadeOnceAndKept(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); !errors.Is(err, ErrNoKey) {
		t.Fatalf("an empty config dir has no key, got %v", err)
	}
	k, err := OpenOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if k.Kind() != KindFile {
		t.Fatalf("kind %q", k.Kind())
	}
	info, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the key file is readable by others: %v", info.Mode())
	}
	again, err := OpenOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Public().Equal(k.Public()) {
		t.Fatal("a second call made a new key instead of returning the first")
	}
	d := sha256.Sum256([]byte("m"))
	sig, err := again.Sign(d[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(k.Public(), d[:], sig) {
		t.Fatal("signature does not verify")
	}
}

func TestACorruptKeyFileIsAnErrorNotANewKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOrCreate(dir); err == nil || errors.Is(err, ErrNoKey) {
		t.Fatalf("a corrupt key must be reported, not silently replaced: %v", err)
	}
}
