package checks

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The access service sends checks as {name, enabled, check_type, severity,
// params}. Before CheckConfig read check_type, every one of them arrived with
// an empty type.
func TestCheckConfigReadsTheServersShape(t *testing.T) {
	var cfg CheckConfig
	require.NoError(t, json.Unmarshal([]byte(`{"name":"os_version","enabled":true,
		"check_type":"os_version","severity":"high","params":{"min_version":"10.0.19045"}}`), &cfg))
	assert.Equal(t, "os_version", cfg.Type)
	assert.Equal(t, "high", cfg.Severity)
	assert.Equal(t, "10.0.19045", cfg.Params["min_version"])
	assert.False(t, cfg.Disabled)
}

func TestCheckConfigStillReadsItsOwnShape(t *testing.T) {
	var cfg CheckConfig
	require.NoError(t, json.Unmarshal([]byte(`{"type":"firewall","severity":"medium","interval":"15m",
		"params":{"profiles":["domain"]}}`), &cfg))
	assert.Equal(t, "firewall", cfg.Type)
	assert.Equal(t, "15m", cfg.Interval)
	assert.Equal(t, []interface{}{"domain"}, cfg.Params["profiles"])
}

func TestCheckConfigTypeOrder(t *testing.T) {
	cases := map[string]string{
		`{"type":"a","check_type":"b","name":"c"}`: "a",
		`{"check_type":"b","name":"c"}`:            "b",
		`{"name":"c"}`:                             "c",
		`{}`:                                       "",
	}
	for in, want := range cases {
		var cfg CheckConfig
		require.NoError(t, json.Unmarshal([]byte(in), &cfg), in)
		assert.Equal(t, want, cfg.Type, in)
	}
}

// A malformed params value costs that check its params, not the whole
// config: failing the decode would replace every configured check with the
// agent's defaults.
func TestCheckConfigIgnoresParamsThatAreNotAnObject(t *testing.T) {
	var list []CheckConfig
	require.NoError(t, json.Unmarshal([]byte(`[
		{"check_type":"os_version","params":"10.0"},
		{"check_type":"firewall","params":null},
		{"check_type":"antivirus","params":{"require_realtime":true}}]`), &list))
	require.Len(t, list, 3)
	assert.Equal(t, "os_version", list[0].Type)
	assert.Nil(t, list[0].Params)
	assert.Nil(t, list[1].Params)
	assert.Equal(t, true, list[2].Params["require_realtime"])
}

func TestCheckConfigEnabled(t *testing.T) {
	var off, on, unset CheckConfig
	require.NoError(t, json.Unmarshal([]byte(`{"check_type":"x","enabled":false}`), &off))
	require.NoError(t, json.Unmarshal([]byte(`{"check_type":"x","enabled":true}`), &on))
	require.NoError(t, json.Unmarshal([]byte(`{"check_type":"x"}`), &unset))
	assert.True(t, off.Disabled)
	assert.False(t, on.Disabled)
	assert.False(t, unset.Disabled, "a check the server lists without enabled is on")
}

type countingCheck struct{ runs int }

func (c *countingCheck) Name() string { return "counting" }
func (c *countingCheck) Run(context.Context, map[string]interface{}) *CheckResult {
	c.runs++
	return &CheckResult{Status: StatusPass, Score: 1}
}

func TestEngineSkipsDisabledChecks(t *testing.T) {
	reg := NewRegistry()
	chk := &countingCheck{}
	reg.Register("counting", chk)
	results := NewEngine(reg).RunChecks(context.Background(), []CheckConfig{
		{Type: "counting", Disabled: true},
		{Type: "counting"},
	})
	assert.Len(t, results, 1, "the disabled check produces no result")
	assert.Equal(t, 1, chk.runs)
}
