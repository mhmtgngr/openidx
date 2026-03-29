package checks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentVersionCheck_Name(t *testing.T) {
	c := &AgentVersionCheck{}
	assert.Equal(t, "agent_version", c.Name())
}

func TestAgentVersionCheck_Run_NilParams(t *testing.T) {
	c := &AgentVersionCheck{}
	result := c.Run(context.Background(), nil)
	require.NotNil(t, result)
	assert.Contains(t, []Status{StatusPass, StatusFail, StatusWarn, StatusError}, result.Status)
}

func TestAgentVersionCheck_Run_NoMinVersion(t *testing.T) {
	c := &AgentVersionCheck{}
	result := c.Run(context.Background(), map[string]interface{}{})
	require.NotNil(t, result)
	assert.Equal(t, StatusPass, result.Status)
}

func TestAgentVersionCheck_Run_DevBuildFails(t *testing.T) {
	orig := AgentVersion
	AgentVersion = "dev"
	defer func() { AgentVersion = orig }()

	c := &AgentVersionCheck{}
	result := c.Run(context.Background(), map[string]interface{}{"min_version": "1.0.0"})
	require.NotNil(t, result)
	assert.Equal(t, StatusFail, result.Status)
	assert.NotEmpty(t, result.Remediation)
}

func TestAgentVersionCheck_Run_SufficientVersion(t *testing.T) {
	orig := AgentVersion
	AgentVersion = "2.0.0"
	defer func() { AgentVersion = orig }()

	c := &AgentVersionCheck{}
	result := c.Run(context.Background(), map[string]interface{}{"min_version": "1.5.0"})
	require.NotNil(t, result)
	assert.Equal(t, StatusPass, result.Status)
	assert.Equal(t, 1.0, result.Score)
}

func TestAgentVersionCheck_Run_InsufficientVersion(t *testing.T) {
	orig := AgentVersion
	AgentVersion = "1.0.0"
	defer func() { AgentVersion = orig }()

	c := &AgentVersionCheck{}
	result := c.Run(context.Background(), map[string]interface{}{"min_version": "2.0.0"})
	require.NotNil(t, result)
	assert.Equal(t, StatusFail, result.Status)
	assert.Equal(t, float64(0), result.Score)
	assert.NotEmpty(t, result.Remediation)
}

func TestAgentVersionCheck_Run_ExactVersion(t *testing.T) {
	orig := AgentVersion
	AgentVersion = "1.5.3"
	defer func() { AgentVersion = orig }()

	c := &AgentVersionCheck{}
	result := c.Run(context.Background(), map[string]interface{}{"min_version": "1.5.3"})
	require.NotNil(t, result)
	assert.Equal(t, StatusPass, result.Status)
}

func TestAgentVersionCheck_Run_DetailsContainVersion(t *testing.T) {
	orig := AgentVersion
	AgentVersion = "3.1.0"
	defer func() { AgentVersion = orig }()

	c := &AgentVersionCheck{}
	result := c.Run(context.Background(), map[string]interface{}{"min_version": "1.0.0"})
	require.NotNil(t, result)
	require.NotNil(t, result.Details)
	assert.Equal(t, "3.1.0", result.Details["agent_version"])
}
