//go:build !windows

package devicekey

// Open returns this device's key, or ErrNoKey when it has none. Off Windows
// the key is a file in configDir.
func Open(configDir string) (Key, error) { return openFileKey(configDir) }

// OpenOrCreate returns this device's key, making one when there is none.
func OpenOrCreate(configDir string) (Key, error) {
	k, err := openFileKey(configDir)
	if err == ErrNoKey {
		return createFileKey(configDir)
	}
	return k, err
}
