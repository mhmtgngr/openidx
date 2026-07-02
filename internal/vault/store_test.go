package vault

import (
	"encoding/json"
	"strings"
	"testing"
)

// SecretMeta / SecretDetail must have NO field that could carry a plaintext value.
func TestDTOsHaveNoValueField(t *testing.T) {
	for _, v := range []interface{}{SecretMeta{}, SecretDetail{}, VersionMeta{}} {
		b, _ := json.Marshal(v)
		if strings.Contains(strings.ToLower(string(b)), "\"value\"") ||
			strings.Contains(strings.ToLower(string(b)), "\"ciphertext\"") ||
			strings.Contains(strings.ToLower(string(b)), "\"plaintext\"") {
			t.Fatalf("DTO %T exposes a value/ciphertext field: %s", v, b)
		}
	}
}
