package credentials

import (
	"bytes"
	"testing"
)

func TestGenerateSecretLengthAndCharset(t *testing.T) {
	v, err := generateSecret(GenerationPolicy{Length: 20, Lower: true, Digits: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 20 {
		t.Fatalf("len=%d want 20", len(v))
	}
	for _, c := range v {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Fatalf("char %q outside requested charset", c)
		}
	}
}

func TestGenerateSecretRejectsShort(t *testing.T) {
	if _, err := generateSecret(GenerationPolicy{Length: 4}); err == nil {
		t.Fatal("expected error for length < 8")
	}
}

func TestGenerateSecretDefaultsAndEntropy(t *testing.T) {
	a, _ := generateSecret(GenerationPolicy{}) // defaults: len 24, all classes
	b, _ := generateSecret(GenerationPolicy{})
	if len(a) != 24 {
		t.Fatalf("default len=%d want 24", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated secrets identical — not random")
	}
}
