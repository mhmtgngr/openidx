package access

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Variable resolution ----

func TestResolveVariable(t *testing.T) {
	ctx := &PolicyContext{
		UserEmail:     "test@example.com",
		UserRoles:     []string{"admin", "user"},
		RequestIP:     "10.0.0.1",
		DeviceTrusted: true,
		PostureScore:  0.85,
		TimeHour:      14,
		GeoCountry:    "US",
		RiskScore:     42,
		RequestMethod: "GET",
		RequestPath:   "/api/v1/users",
	}

	tests := []struct {
		variable string
		expected interface{}
	}{
		{"user.email", "test@example.com"},
		{"user.roles", []string{"admin", "user"}},
		{"request.ip", "10.0.0.1"},
		{"device.trusted", true},
		{"device.posture_score", 0.85},
		{"time.hour", float64(14)},
		{"geo.country", "US"},
		{"session.risk_score", float64(42)},
		{"request.method", "GET"},
		{"request.path", "/api/v1/users"},
		{"unknown.var", nil},
	}

	for _, tt := range tests {
		t.Run(tt.variable, func(t *testing.T) {
			result := resolveVariable(tt.variable, ctx)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---- Parsing ----

func TestParsePolicy_ValidExpressions(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"simple equality", `user.email == "admin@test.com"`},
		{"boolean", `device.trusted == true`},
		{"numeric comparison", `device.posture_score > 0.5`},
		{"in array", `user.roles in ["admin", "super_admin"]`},
		{"contains", `request.path contains "/api"`},
		{"matches", `user.email matches ".*@example\\.com"`},
		{"AND", `device.trusted == true AND device.posture_score > 0.5`},
		{"OR", `user.email == "a@b.com" OR user.email == "c@d.com"`},
		{"NOT", `NOT user.email == "bad@evil.com"`},
		{"nested parens", `(user.email == "a@b.com" OR user.email == "c@d.com") AND device.trusted == true`},
		{"not_in", `geo.country not_in ["CN", "RU"]`},
		{"numeric <=", `time.hour <= 18`},
		{"numeric >=", `time.hour >= 9`},
		{"inequality", `user.email != "blocked@test.com"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParsePolicy(tt.expr)
			require.NoError(t, err)
			assert.NotNil(t, node)
		})
	}
}

func TestParsePolicy_InvalidExpressions(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{"empty", ""},
		{"unbalanced parens", `(user.email == "a@b.com"`},
		{"missing operator", `user.email "test"`},
		{"missing value", `user.email ==`},
		{"double operator", `user.email == == "test"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy(tt.expr)
			assert.Error(t, err)
		})
	}
}

// ---- Evaluation ----

func TestEvaluatePolicy_Equality(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "admin@test.com"}
	result, err := EvaluatePolicyString(`user.email == "admin@test.com"`, ctx)
	require.NoError(t, err)
	assert.True(t, result)

	result, err = EvaluatePolicyString(`user.email == "other@test.com"`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_Inequality(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "admin@test.com"}
	result, err := EvaluatePolicyString(`user.email != "other@test.com"`, ctx)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestEvaluatePolicy_InArray(t *testing.T) {
	ctx := &PolicyContext{UserRoles: []string{"admin", "editor"}}

	result, err := EvaluatePolicyString(`user.roles in ["admin", "super_admin"]`, ctx)
	require.NoError(t, err)
	assert.True(t, result) // "admin" is in the target array

	result, err = EvaluatePolicyString(`user.roles in ["viewer"]`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_NotIn(t *testing.T) {
	ctx := &PolicyContext{GeoCountry: "US"}

	result, err := EvaluatePolicyString(`geo.country not_in ["CN", "RU"]`, ctx)
	require.NoError(t, err)
	assert.True(t, result)

	result, err = EvaluatePolicyString(`geo.country not_in ["US", "GB"]`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_Contains(t *testing.T) {
	ctx := &PolicyContext{RequestPath: "/api/v1/users/123"}

	result, err := EvaluatePolicyString(`request.path contains "/api"`, ctx)
	require.NoError(t, err)
	assert.True(t, result)

	result, err = EvaluatePolicyString(`request.path contains "/admin"`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_Matches(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "admin@example.com"}

	result, err := EvaluatePolicyString(`user.email matches ".*@example\.com"`, ctx)
	require.NoError(t, err)
	assert.True(t, result)

	result, err = EvaluatePolicyString(`user.email matches ".*@other\.com"`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_NumericComparisons(t *testing.T) {
	ctx := &PolicyContext{TimeHour: 14, PostureScore: 0.8, RiskScore: 50}

	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{"greater than true", `time.hour > 9`, true},
		{"greater than false", `time.hour > 18`, false},
		{"less than true", `time.hour < 18`, true},
		{"less than false", `time.hour < 10`, false},
		{"gte true", `time.hour >= 14`, true},
		{"gte false", `time.hour >= 15`, false},
		{"lte true", `time.hour <= 14`, true},
		{"lte false", `time.hour <= 13`, false},
		{"posture score", `device.posture_score > 0.5`, true},
		{"risk score", `session.risk_score < 80`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EvaluatePolicyString(tt.expr, ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluatePolicy_AND(t *testing.T) {
	ctx := &PolicyContext{
		UserEmail:     "admin@example.com",
		DeviceTrusted: true,
	}

	result, err := EvaluatePolicyString(`user.email == "admin@example.com" AND device.trusted == true`, ctx)
	require.NoError(t, err)
	assert.True(t, result)

	result, err = EvaluatePolicyString(`user.email == "admin@example.com" AND device.trusted == false`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_OR(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "admin@example.com"}

	result, err := EvaluatePolicyString(`user.email == "admin@example.com" OR user.email == "other@test.com"`, ctx)
	require.NoError(t, err)
	assert.True(t, result)

	result, err = EvaluatePolicyString(`user.email == "wrong@test.com" OR user.email == "other@test.com"`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_NOT(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "admin@example.com"}

	result, err := EvaluatePolicyString(`NOT user.email == "blocked@evil.com"`, ctx)
	require.NoError(t, err)
	assert.True(t, result)

	result, err = EvaluatePolicyString(`NOT user.email == "admin@example.com"`, ctx)
	require.NoError(t, err)
	assert.False(t, result)
}

func TestEvaluatePolicy_NestedExpressions(t *testing.T) {
	ctx := &PolicyContext{
		UserEmail:     "admin@example.com",
		DeviceTrusted: true,
		GeoCountry:    "US",
	}

	expr := `(user.email == "admin@example.com" OR user.email == "root@example.com") AND device.trusted == true AND geo.country == "US"`
	result, err := EvaluatePolicyString(expr, ctx)
	require.NoError(t, err)
	assert.True(t, result)
}

func TestEvaluatePolicy_TimeBased(t *testing.T) {
	ctx := &PolicyContext{TimeHour: 14}

	result, err := EvaluatePolicyString(`time.hour >= 9 AND time.hour <= 17`, ctx)
	require.NoError(t, err)
	assert.True(t, result) // business hours

	ctx.TimeHour = 22
	result, err = EvaluatePolicyString(`time.hour >= 9 AND time.hour <= 17`, ctx)
	require.NoError(t, err)
	assert.False(t, result) // outside business hours
}

// ---- Error cases ----

func TestEvaluatePolicy_InvalidRegex(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "test@example.com"}
	_, err := EvaluatePolicyString(`user.email matches "["`, ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "regex")
}

func TestEvaluatePolicy_RegexTooLong(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "test@example.com"}
	longPattern := strings.Repeat("a", 201)
	_, err := EvaluatePolicyString(`user.email matches "`+longPattern+`"`, ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestEvaluatePolicy_InRequiresArray(t *testing.T) {
	ctx := &PolicyContext{UserEmail: "test@example.com"}
	// "in" requires an array, not a string
	_, err := EvaluatePolicyString(`user.email in "admin"`, ctx)
	assert.Error(t, err)
}

// ---- ValidatePolicy ----

func TestValidatePolicy_Valid(t *testing.T) {
	assert.NoError(t, ValidatePolicy(`user.email == "admin@test.com"`))
	assert.NoError(t, ValidatePolicy(`device.trusted == true AND device.posture_score > 0.5`))
	assert.NoError(t, ValidatePolicy(`(geo.country == "US" OR geo.country == "GB") AND time.hour >= 9`))
}

func TestValidatePolicy_Invalid(t *testing.T) {
	assert.Error(t, ValidatePolicy(""))
	assert.Error(t, ValidatePolicy("not a valid expression"))
	assert.Error(t, ValidatePolicy(`(user.email == "test"`)) // unbalanced
}

// ---- Tokenizer edge cases ----

func TestTokenize_Whitespace(t *testing.T) {
	tokens, err := tokenize(`  user.email   ==   "test"  `)
	require.NoError(t, err)
	// Should have: variable, operator, string, EOF
	assert.Equal(t, 4, len(tokens))
	assert.Equal(t, tokVariable, tokens[0].typ)
	assert.Equal(t, tokOperator, tokens[1].typ)
	assert.Equal(t, tokString, tokens[2].typ)
	assert.Equal(t, tokEOF, tokens[3].typ)
}

func TestTokenize_UnterminatedString(t *testing.T) {
	_, err := tokenize(`user.email == "unterminated`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated")
}

func TestTokenize_EscapedQuotes(t *testing.T) {
	tokens, err := tokenize(`user.email == "test\"quoted"`)
	require.NoError(t, err)
	assert.Equal(t, `test"quoted`, tokens[2].val)
}

func TestTokenize_EmptyArray(t *testing.T) {
	tokens, err := tokenize(`user.roles in []`)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(tokens), 4) // var, op, [, ], EOF
}
