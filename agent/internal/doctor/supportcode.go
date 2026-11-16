package doctor

import (
	"encoding/base32"
	"fmt"
	"strings"
)

// A support code is what a user reads to IT over the phone when the device
// cannot reach the server: which checks failed, and nothing else. It holds no
// host name, address or identifier. Bit i stands for AllCodes[i], so AllCodes
// is append-only.

const supportPrefix = "OX1"

var supportEnc = base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").WithPadding(base32.NoPadding)

// SupportCode encodes the bundle's failing and warning codes.
func SupportCode(b Bundle) string {
	bits := make([]byte, (len(AllCodes)+7)/8)
	for _, c := range b.Checks {
		if c.Status != StatusFail && c.Status != StatusWarn {
			continue
		}
		for i, code := range AllCodes {
			if code == c.Code {
				bits[i/8] |= 1 << (i % 8)
			}
		}
	}
	s := supportEnc.EncodeToString(append(bits, checksum(bits)))
	var parts []string
	for len(s) > 4 {
		parts, s = append(parts, s[:4]), s[4:]
	}
	return supportPrefix + "-" + strings.Join(append(parts, s), "-")
}

// DecodeSupportCode returns the cause codes a support code names. It forgives
// case, spaces and dashes, and refuses a code that was mistyped.
func DecodeSupportCode(s string) ([]string, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
	body, ok := strings.CutPrefix(s, supportPrefix)
	if !ok {
		return nil, fmt.Errorf("not an OpenIDX support code")
	}
	raw, err := supportEnc.DecodeString(body)
	if err != nil || len(raw) < 2 {
		return nil, fmt.Errorf("support code is damaged")
	}
	bits, sum := raw[:len(raw)-1], raw[len(raw)-1]
	if checksum(bits) != sum {
		return nil, fmt.Errorf("support code was mistyped")
	}
	codes := []string{}
	for i, code := range AllCodes {
		if i/8 < len(bits) && bits[i/8]&(1<<(i%8)) != 0 {
			codes = append(codes, code)
		}
	}
	return codes, nil
}

func checksum(b []byte) byte {
	sum := byte(0x5a)
	for i, v := range b {
		sum = sum<<1 | sum>>7
		sum ^= v + byte(i)
	}
	return sum
}
