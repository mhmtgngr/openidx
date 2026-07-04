// Package credentials implements the PAM credential rotation engine: it generates new
// credential values, applies them to target systems through Rotator connectors, verifies
// them, and promotes them as the vault's current version.
package credentials

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// ErrVerifyUnsupported signals a connector cannot verify a credential is live; the engine
// treats it as "skip verification" (not a failure).
var ErrVerifyUnsupported = errors.New("credentials: connector cannot verify")

// Rotator applies (and optionally verifies) a new credential value on a target system.
type Rotator interface {
	Type() string
	Apply(ctx context.Context, cfg map[string]any, newValue []byte) error
	Verify(ctx context.Context, cfg map[string]any, newValue []byte) error
}

// ValueGenerator lets a connector produce the secret value itself (e.g. an SSH private key)
// instead of the engine's default random-password generateSecret. Optional: connectors that
// don't implement it keep using generateSecret.
type ValueGenerator interface {
	Generate(gp GenerationPolicy) ([]byte, error)
}

// GenerationPolicy controls generateSecret. Zero value → length 24, all character classes.
type GenerationPolicy struct {
	Length  int  `json:"length"`
	Upper   bool `json:"upper"`
	Lower   bool `json:"lower"`
	Digits  bool `json:"digits"`
	Symbols bool `json:"symbols"`
}

const (
	setUpper  = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I/O
	setLower  = "abcdefghijkmnopqrstuvwxyz"
	setDigits = "23456789"
	setSym    = "!@#$%^&*()-_=+"
)

// generateSecret builds a cryptographically-random value per gp using crypto/rand.
func generateSecret(gp GenerationPolicy) ([]byte, error) {
	if gp.Length == 0 {
		gp.Length = 24
	}
	if gp.Length < 8 {
		return nil, fmt.Errorf("generation length must be >= 8, got %d", gp.Length)
	}
	var charset []byte
	if gp.Upper {
		charset = append(charset, setUpper...)
	}
	if gp.Lower {
		charset = append(charset, setLower...)
	}
	if gp.Digits {
		charset = append(charset, setDigits...)
	}
	if gp.Symbols {
		charset = append(charset, setSym...)
	}
	if len(charset) == 0 { // no class requested → use all
		charset = []byte(setUpper + setLower + setDigits + setSym)
	}
	out := make([]byte, gp.Length)
	max := big.NewInt(int64(len(charset)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("rand: %w", err)
		}
		out[i] = charset[n.Int64()]
	}
	return out, nil
}
