package devicekey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/openidx/openidx/agent/internal/secretfile"
)

// keyFileName is the file key's name in the config directory.
const keyFileName = "device-key.pem"

// fileKey is a P-256 key held in memory, loaded from a file.
type fileKey struct{ priv *ecdsa.PrivateKey }

func (k *fileKey) Public() *ecdsa.PublicKey { return &k.priv.PublicKey }
func (k *fileKey) Kind() string             { return KindFile }
func (k *fileKey) Close()                   {}
func (k *fileKey) Sign(digest []byte) ([]byte, error) {
	return k.priv.Sign(rand.Reader, digest, crypto.SHA256)
}

// openFileKey loads the key file in dir, or ErrNoKey when there is none.
func openFileKey(dir string) (Key, error) {
	raw, err := secretfile.Read(filepath.Join(dir, keyFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, fmt.Errorf("read the device key: %w", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("the device key file is not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse the device key: %w", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("the device key is not an ECDSA P-256 key")
	}
	return &fileKey{priv: priv}, nil
}

// createFileKey makes a new key and writes it to dir, readable by its owner
// only (secretfile.Write).
func createFileKey(dir string) (Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate the device key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("encode the device key: %w", err)
	}
	if err := secretfile.Write(filepath.Join(dir, keyFileName),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, fmt.Errorf("store the device key: %w", err)
	}
	return &fileKey{priv: priv}, nil
}
