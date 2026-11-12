package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiskEncryptionCheck_Name(t *testing.T) {
	c := &DiskEncryptionCheck{}
	assert.Equal(t, "disk_encryption", c.Name())
}

func TestDiskEncryptionCheck_Run_NilParams(t *testing.T) {
	// Run() accepts nil params without panicking; the result must be non-nil
	// and carry a valid status.
	c := &DiskEncryptionCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestDiskEncryptionCheck_Run_ReturnsDetails(t *testing.T) {
	c := &DiskEncryptionCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)

	// On Linux the check uses lsblk; on macOS it uses fdesetup; on other
	// platforms it returns StatusWarn.  In every case the Details map must
	// carry the "os" key.
	require.NotNil(t, result.Details)
	assert.NotEmpty(t, result.Details["os"])
}

func TestDiskEncryptionCheck_Run_HasMessage(t *testing.T) {
	c := &DiskEncryptionCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Message)
}

// TestDiskEncryptionCheck_Run_FailHasRemediation verifies that when the status
// is StatusFail a remediation hint is provided.
func TestDiskEncryptionCheck_Run_FailHasRemediation(t *testing.T) {
	c := &DiskEncryptionCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	if result.Status == StatusFail {
		assert.NotEmpty(t, result.Remediation, "failed check should include a remediation message")
	}
}

// TestDiskEncryptionCheck_Run_ScoreRange verifies that the score is always
// between 0 and 1 inclusive.
func TestDiskEncryptionCheck_Run_ScoreRange(t *testing.T) {
	c := &DiskEncryptionCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Score, float64(0))
	assert.LessOrEqual(t, result.Score, float64(1))
}

// The service ran manage-bde by bare name, which Go refuses to resolve from
// the working directory, so every Windows device reported an error.
func TestManageBdeIsRunByAbsolutePath(t *testing.T) {
	t.Setenv("SystemRoot", `D:\Win`)
	p := manageBdePath()
	assert.Contains(t, p, "System32")
	assert.Contains(t, p, "manage-bde.exe")
	assert.True(t, len(p) > len("manage-bde.exe"), "must not be a bare name: %q", p)

	t.Setenv("SystemRoot", "")
	assert.Contains(t, manageBdePath(), "Windows")
}
