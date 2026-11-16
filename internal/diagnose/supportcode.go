package diagnose

import (
	"encoding/base32"
	"fmt"
	"strings"
)

// A support code is what a user reads to IT when the device cannot reach the
// server: a bitset of the doctor's failing and warning codes plus a checksum.
// The agent writes it (agent/internal/doctor/supportcode.go); this is the
// reader. Bit i stands for doctorCodes[i], so the list is append-only on both
// sides, and TestSupportCodesFromTheAgentDecode holds the two together.

const supportPrefix = "OX1"

var supportEnc = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").WithPadding(base32.NoPadding)

var doctorCodes = []string{
	"CONFIG_UNREADABLE", "NOT_ENROLLED", "AUTH_INVALID", "DEVICE_REVOKED",
	"DNS_FAIL", "DNS_TIMEOUT", "TCP_BLOCKED", "TCP_TIMEOUT",
	"TLS_UNTRUSTED", "TLS_FAIL", "PROXY_AUTH_REQUIRED", "SERVER_HTTP_ERROR",
	"HTTP_TIMEOUT", "HTTP_FAIL", "CLOCK_SKEW", "IDENTITY_MISSING",
	"IDENTITY_EXPIRED", "IDENTITY_EXPIRING", "IDENTITY_INVALID",
	"SERVICE_NOT_RUNNING", "TUNNEL_DOWN", "TUNNEL_NOT_INSTALLED",
	"TUNNEL_OFF", "INTERNAL",
}

// ErrSupportCode is wrapped by every reason a support code is refused.
var ErrSupportCode = fmt.Errorf("invalid support code")

// DecodeSupportCode returns the doctor codes a support code names. It
// forgives case, spaces and dashes, and refuses a code that was mistyped.
func DecodeSupportCode(s string) ([]string, error) {
	if len(s) > 128 {
		return nil, fmt.Errorf("%w: too long", ErrSupportCode)
	}
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
	body, ok := strings.CutPrefix(s, supportPrefix)
	if !ok {
		return nil, fmt.Errorf("%w: not an OpenIDX support code", ErrSupportCode)
	}
	raw, err := supportEnc.DecodeString(body)
	if err != nil || len(raw) < 2 {
		return nil, fmt.Errorf("%w: damaged", ErrSupportCode)
	}
	bits, sum := raw[:len(raw)-1], raw[len(raw)-1]
	if supportChecksum(bits) != sum {
		return nil, fmt.Errorf("%w: mistyped", ErrSupportCode)
	}
	codes := []string{}
	for i, code := range doctorCodes {
		if i/8 < len(bits) && bits[i/8]&(1<<(i%8)) != 0 {
			codes = append(codes, code)
		}
	}
	return codes, nil
}

func supportChecksum(b []byte) byte {
	sum := byte(0x5a)
	for i, v := range b {
		sum = sum<<1 | sum>>7
		sum ^= v + byte(i)
	}
	return sum
}

// BundleFromCodes is the bundle a support code stands for: the named codes
// as failing checks, and nothing else known.
func BundleFromCodes(codes []string) *Bundle {
	b := &Bundle{Schema: BundleSchema, Checks: []Check{}, Repairs: []Repair{}}
	for _, c := range codes {
		b.Checks = append(b.Checks, Check{ID: "support_code", Status: StatusFail, Code: c})
	}
	return b
}
