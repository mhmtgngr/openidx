//go:build windows

package devicekey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DefaultKeyName names the agent's machine key in the key storage providers.
const DefaultKeyName = "OpenIDX Agent Device Key"

const (
	providerPlatform = "Microsoft Platform Crypto Provider"
	providerSoftware = "Microsoft Software Key Storage Provider"
	algECDSAP256     = "ECDSA_P256"
	blobECCPublic    = "ECCPUBLICBLOB"

	machineKeyFlag = 0x20 // NCRYPT_MACHINE_KEY_FLAG
	silentFlag     = 0x40 // NCRYPT_SILENT_FLAG: a service has no one to show a prompt to

	nteBadKeyset = 0x80090016 // NTE_BAD_KEYSET: no key by that name
)

var (
	ncrypt                  = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
	procDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
)

// ncryptError is a SECURITY_STATUS other than ERROR_SUCCESS.
type ncryptError uint32

func (e ncryptError) Error() string { return fmt.Sprintf("NCrypt status 0x%08X", uint32(e)) }

func status(r uintptr) error {
	if s := uint32(r); s != 0 {
		return ncryptError(s)
	}
	return nil
}

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func freeObject(h uintptr) {
	if h != 0 {
		_, _, _ = procFreeObject.Call(h)
	}
}

// ncryptKey is a persisted key in a key storage provider. Its private half
// never enters this process: Sign hands the digest to the provider.
type ncryptKey struct {
	prov, key uintptr
	kind      string
	pub       *ecdsa.PublicKey
}

func (k *ncryptKey) Public() *ecdsa.PublicKey { return k.pub }
func (k *ncryptKey) Kind() string             { return k.kind }

func (k *ncryptKey) Close() {
	freeObject(k.key)
	freeObject(k.prov)
	k.key, k.prov = 0, 0
}

func (k *ncryptKey) Sign(digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}
	var size uint32
	r, _, _ := procSignHash.Call(k.key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0, uintptr(unsafe.Pointer(&size)), silentFlag)
	if err := status(r); err != nil {
		return nil, fmt.Errorf("size the signature: %w", err)
	}
	if size == 0 {
		return nil, errors.New("the provider reported an empty signature")
	}
	sig := make([]byte, size)
	r, _, _ = procSignHash.Call(k.key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), silentFlag)
	if err := status(r); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return rawSignatureToASN1(sig[:size])
}

// openProvider opens a key storage provider.
func openProvider(name string) (uintptr, error) {
	var h uintptr
	r, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16(name))), 0)
	if err := status(r); err != nil {
		return 0, err
	}
	return h, nil
}

// exportPublic reads the key's public half.
func exportPublic(key uintptr) (*ecdsa.PublicKey, error) {
	blob := utf16(blobECCPublic)
	var size uint32
	r, _, _ := procExportKey.Call(key, 0, uintptr(unsafe.Pointer(blob)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if err := status(r); err != nil {
		return nil, fmt.Errorf("size the public key: %w", err)
	}
	if size == 0 {
		return nil, errors.New("the provider reported an empty public key")
	}
	buf := make([]byte, size)
	r, _, _ = procExportKey.Call(key, 0, uintptr(unsafe.Pointer(blob)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	if err := status(r); err != nil {
		return nil, fmt.Errorf("export the public key: %w", err)
	}
	return parseECCPublicBlob(buf[:size])
}

// errProviderUnavailable: the key storage provider itself could not be
// opened, typically the Platform Crypto Provider on a machine with no TPM.
var errProviderUnavailable = errors.New("key storage provider unavailable")

// openIn opens the named key in one provider. ok=false with a nil error
// means the provider is there and holds no such key.
func openIn(provider, kind, name string, flags uintptr) (k *ncryptKey, ok bool, err error) {
	prov, err := openProvider(provider)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %v", errProviderUnavailable, provider, err)
	}
	var key uintptr
	r, _, _ := procOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(utf16(name))), 0, flags|silentFlag)
	if s := uint32(r); s == nteBadKeyset {
		freeObject(prov)
		return nil, false, nil
	} else if s != 0 {
		freeObject(prov)
		return nil, false, ncryptError(s)
	}
	pub, err := exportPublic(key)
	if err != nil {
		freeObject(key)
		freeObject(prov)
		return nil, false, err
	}
	return &ncryptKey{prov: prov, key: key, kind: kind, pub: pub}, true, nil
}

// createIn makes the named P-256 key in one provider. The provider's default
// export policy for a new key is none, so the private half cannot be read
// back out; for the Platform Crypto Provider it never leaves the TPM.
func createIn(provider, kind, name string, flags uintptr) (*ncryptKey, error) {
	prov, err := openProvider(provider)
	if err != nil {
		return nil, err
	}
	var key uintptr
	r, _, _ := procCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(utf16(algECDSAP256))), uintptr(unsafe.Pointer(utf16(name))), 0, flags)
	if err := status(r); err != nil {
		freeObject(prov)
		return nil, fmt.Errorf("create the key: %w", err)
	}
	r, _, _ = procFinalizeKey.Call(key, silentFlag)
	if err := status(r); err != nil {
		freeObject(key)
		freeObject(prov)
		return nil, fmt.Errorf("finalize the key: %w", err)
	}
	pub, err := exportPublic(key)
	if err != nil {
		freeObject(key)
		freeObject(prov)
		return nil, err
	}
	return &ncryptKey{prov: prov, key: key, kind: kind, pub: pub}, nil
}

// openNamed looks for the key in the TPM first, then in the software store.
// A provider that cannot be opened is skipped (no TPM is not an error); a key
// that is there but cannot be read is an error, not "no key": treating it as
// absent would make a second key and leave the server holding the first.
func openNamed(name string, flags uintptr) (Key, error) {
	for _, p := range []struct{ provider, kind string }{
		{providerPlatform, KindTPM},
		{providerSoftware, KindSoftware},
	} {
		k, ok, err := openIn(p.provider, p.kind, name, flags)
		if errors.Is(err, errProviderUnavailable) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if ok {
			return k, nil
		}
	}
	return nil, ErrNoKey
}

// createNamed makes the key in the TPM, or in the software store when the
// TPM cannot hold it (none, disabled, or a virtual machine without one).
func createNamed(name string, flags uintptr) (Key, error) {
	k, tpmErr := createIn(providerPlatform, KindTPM, name, flags)
	if tpmErr == nil {
		return k, nil
	}
	k, swErr := createIn(providerSoftware, KindSoftware, name, flags)
	if swErr != nil {
		return nil, fmt.Errorf("no key storage provider could create the device key: TPM: %v; software: %v", tpmErr, swErr)
	}
	return k, nil
}

// deleteNamed removes the named key from whichever provider holds it. For
// tests.
func deleteNamed(name string, flags uintptr) error {
	for _, p := range []string{providerPlatform, providerSoftware} {
		k, ok, err := openIn(p, "", name, flags)
		if err != nil || !ok {
			continue
		}
		r, _, _ := procDeleteKey.Call(k.key, 0)
		freeObject(k.prov) // NCryptDeleteKey frees the key handle itself
		if err := status(r); err != nil {
			return err
		}
	}
	return nil
}

// Open returns this machine's device key, or ErrNoKey when it has none. The
// key is a machine key, so configDir is not used on Windows.
func Open(_ string) (Key, error) { return openNamed(DefaultKeyName, machineKeyFlag) }

// OpenOrCreate returns this machine's device key, making one when there is
// none. Making a machine key needs the service's or an administrator's
// rights; the tray never calls this.
func OpenOrCreate(_ string) (Key, error) {
	k, err := openNamed(DefaultKeyName, machineKeyFlag)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, ErrNoKey) {
		return nil, err
	}
	return createNamed(DefaultKeyName, machineKeyFlag|silentFlag)
}
