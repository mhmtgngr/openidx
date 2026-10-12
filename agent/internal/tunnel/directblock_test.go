package tunnel

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitPrefixesMasksDeduplicatesAndRefusesGarbage(t *testing.T) {
	v4, v6, err := splitPrefixes([]string{"10.1.2.3/8", " 10.0.0.0/8", "192.168.1.0/24", "fd00::1/64"})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.1.0/24"}, v4)
	assert.Equal(t, []string{"fd00::/64"}, v6)

	// Anything that is not a prefix fails the whole set: it would otherwise be
	// written into the nft script, and a partial block is not the policy.
	for _, bad := range []string{"10.0.0.0/8; flush ruleset", "example.com", "10.0.0.0/33", ""} {
		_, _, err := splitPrefixes([]string{"10.0.0.0/8", bad})
		assert.Error(t, err, bad)
	}
}

func TestDirectBlockScriptRejectsTheRangesOutsideTheTunnel(t *testing.T) {
	s := directBlockScript([]string{"10.0.0.0/8"}, nil)
	// Replaced in one transaction: declare, delete, recreate.
	assert.True(t, strings.HasPrefix(s, "table inet openidx_direct\ndelete table inet openidx_direct\ntable inet openidx_direct {\n"), s)
	for _, want := range []string{
		"elements = { 10.0.0.0/8 }",
		"type filter hook output priority filter; policy accept;",
		"type filter hook forward priority filter; policy accept;",
		`oifname "ziti*" accept`,
		"meta skuid 0 accept",
		"ip daddr @corp4 reject with icmpx type admin-prohibited",
	} {
		assert.Contains(t, s, want)
	}
	assert.NotContains(t, s, "corp6", "an empty family has no set and no rule")
	// Root is let through on the output path only; forwarded traffic has no
	// local socket owner.
	fwd := s[strings.Index(s, "chain forward"):]
	assert.NotContains(t, fwd, "skuid")

	s = directBlockScript(nil, []string{"fd00::/8"})
	assert.Contains(t, s, "ip6 daddr @corp6 reject")
	assert.NotContains(t, s, "corp4")
}

func TestDirectBlockLoadsOnlyWhatChanged(t *testing.T) {
	var scripts []string
	d := NewDirectBlockFunc(func(s string) error { scripts = append(scripts, s); return nil }, func() error { return nil })

	require.NoError(t, d.Apply([]string{"10.0.0.0/8"}))
	require.NoError(t, d.Apply([]string{"10.0.0.0/8"}))
	require.Len(t, scripts, 1, "an unchanged set is not loaded again")
	assert.True(t, d.Active())

	require.NoError(t, d.Apply([]string{"10.0.0.0/8", "172.16.0.0/12"}))
	require.Len(t, scripts, 2)

	require.NoError(t, d.Apply(nil), "an empty set removes the block")
	require.Len(t, scripts, 3)
	assert.Equal(t, clearScript(), scripts[2])
	assert.False(t, d.Active())

	// A failed load leaves the block marked as not loaded, so the next try
	// loads it again.
	fail := errors.New("netlink: permission denied")
	d = NewDirectBlockFunc(func(string) error { return fail }, func() error { return nil })
	assert.ErrorIs(t, d.Apply([]string{"10.0.0.0/8"}), fail)
	assert.False(t, d.Active())
}

func TestDirectBlockRefusesWhereUnsupported(t *testing.T) {
	ran := false
	unsupported := errors.New("no hook")
	d := NewDirectBlockFunc(func(string) error { ran = true; return nil }, func() error { return unsupported })
	assert.ErrorIs(t, d.Apply([]string{"10.0.0.0/8"}), unsupported)
	assert.ErrorIs(t, d.Clear(), unsupported)
	assert.False(t, ran)
}

// TestDirectBlockScriptParses checks the script with nft's own parser
// (nft -c), where nft is installed and this test runs as root.
func TestDirectBlockScriptParses(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil || os.Geteuid() != 0 {
		t.Skip("needs nft and root")
	}
	cmd := exec.Command(nft, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(directBlockScript([]string{"10.0.0.0/8", "192.168.0.0/16"}, []string{"fd00::/8"}))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
