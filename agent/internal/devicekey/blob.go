package devicekey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// eccPublicP256Magic is BCRYPT_ECDSA_PUBLIC_P256_MAGIC ("ECS1").
const eccPublicP256Magic = 0x31534345

// parseECCPublicBlob reads a BCRYPT_ECCPUBLIC_BLOB for P-256, the form
// NCryptExportKey gives a public key in: a BCRYPT_ECCKEY_BLOB header (magic,
// key length) followed by X and Y, big-endian. It lives in an untagged file
// so the parsing is tested on every platform.
func parseECCPublicBlob(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) < 8 {
		return nil, errors.New("ECC public blob is shorter than its header")
	}
	magic := binary.LittleEndian.Uint32(b[0:4])
	size := binary.LittleEndian.Uint32(b[4:8])
	if magic != eccPublicP256Magic || size != 32 {
		return nil, fmt.Errorf("ECC public blob is not P-256 (magic 0x%08X, key length %d)", magic, size)
	}
	if len(b) != 8+64 {
		return nil, fmt.Errorf("ECC public blob is %d bytes, want 72", len(b))
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(b[8:40]),
		Y:     new(big.Int).SetBytes(b[40:72]),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("ECC public blob's point is not on P-256")
	}
	return pub, nil
}

// rawSignatureToASN1 turns NCryptSignHash's r||s (32 bytes each for P-256)
// into the ASN.1 DER form Go and the server verify.
func rawSignatureToASN1(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("P-256 signature is %d bytes, want 64", len(raw))
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:32]),
		S: new(big.Int).SetBytes(raw[32:]),
	})
}
