// Package governance provides Zero Trust policy evaluation for OpenIDX
package governance

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// allowedFields is the allowlist of valid field names that can be used in policy conditions
// This prevents injection attacks via arbitrary field access
var allowedFields = map[string]bool{
	// Subject/User fields
	"subject.id":          true,
	"subject.type":        true,
	"subject.authenticated": true,
	"subject.roles":       true,
	"subject.groups":      true,
	"subject.attributes":  true,
	"user.id":             true,
	"user.type":           true,
	"user.authenticated":  true,
	"user.roles":          true,
	"user.groups":         true,
	"user.attributes":     true,

	// Resource fields
	"resource.id":         true,
	"resource.type":       true,
	"resource.name":       true,
	"resource.owner":      true,
	"resource.path":       true,
	"resource.tags":       true,
	"resource.attributes": true,

	// Context fields
	"context.ip":          true,
	"context.ip_address":  true,
	"context.user_agent":  true,
	"context.time":        true,
	"context.environment": true,
	"context.device_id":   true,
	"context.session_id":  true,
	"context.request_id":  true,
	"context.location":    true,
	"context.attributes":  true,

	// Action field
	"action":              true,
}

// allowedAttributePrefixes defines allowed prefixes for dynamic attribute access
// These are safe because they only access pre-defined map keys, not arbitrary paths
var allowedAttributePrefixes = []string{
	"subject.attributes.",
	"user.attributes.",
	"resource.attributes.",
	"context.attributes.",
}

// isFieldAllowed checks if a field name is in the allowlist or is a safe attribute access
func isFieldAllowed(field string) bool {
	// Check exact match first
	if allowedFields[field] {
		return true
	}

	// Check for safe attribute access patterns
	for _, prefix := range allowedAttributePrefixes {
		if strings.HasPrefix(field, prefix) {
			// Ensure there's something after the prefix
			rest := strings.TrimPrefix(field, prefix)
			if len(rest) > 0 {
				// Validate attribute key contains only safe characters
				// Only allow alphanumeric, underscore, hyphen, and dot for nested keys
				for _, r := range rest {
					if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
						r == '_' || r == '-' || r == '.') {
						return false
					}
				}
				return true
			}
		}
	}

	return false
}

// ZTPolicy represents a Zero Trust access policy with versioning support
type ZTPolicy struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Effect      PolicyEffect    `json:"effect"`
	Conditions  ConditionGroup  `json:"conditions"`
	Priority    int             `json:"priority"`
	Enabled     bool            `json:"enabled"`
	TenantID    string          `json:"tenant_id,omitempty"`
	Version     int             `json:"version"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedBy   string          `json:"created_by,omitempty"`
	UpdatedBy   string          `json:"updated_by,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// PolicyEffect defines the allow/deny effect of a policy
type PolicyEffect string

const (
	EffectAllow PolicyEffect = "allow"
	EffectDeny  PolicyEffect = "deny"
)

// ConditionGroup represents a group of conditions with logical operators
type ConditionGroup struct {
	Operator LogicalOperator `json:"operator"` // and, or, not
	Conditions []Condition    `json:"conditions,omitempty"`
	Groups     []ConditionGroup `json:"groups,omitempty"` // Nested groups
}

// LogicalOperator defines how conditions/groups are combined
type LogicalOperator string

const (
	OpAnd LogicalOperator = "and"
	OpOr  LogicalOperator = "or"
	OpNot LogicalOperator = "not"
)

// Condition represents a single condition to evaluate
type Condition struct {
	Field    string      `json:"field"`     // user.role, resource.type, context.ip, etc.
	Operator string      `json:"operator"`  // equals, contains, in, regex, etc.
	Value    interface{} `json:"value"`     // The value to compare against
	Negated  bool        `json:"negated"`   // If true, negates the condition
}

// Supported condition operators
const (
	OpEquals        = "equals"
	OpNotEquals     = "not_equals"
	OpContains      = "contains"
	OpNotContains   = "not_contains"
	OpStartsWith    = "starts_with"
	OpEndsWith      = "ends_with"
	OpIn            = "in"
	OpNotIn         = "not_in"
	OpGreaterThan   = "greater_than"
	OpLessThan      = "less_than"
	OpRegex         = "regex"
	OpIPInRange     = "ip_in_range"
	OpTimeInRange   = "time_in_range"
	OpDayOfWeek     = "day_of_week"
	OpHasRole       = "has_role"
	OpHasGroup      = "has_group"
	OpHasAttribute  = "has_attribute"
	OpDeviceTrusted = "device_trusted"
	OpLocationMatch = "location_match"
)

// ZTPolicyInput represents input for policy evaluation
type ZTPolicyInput struct {
	Subject  Subject         `json:"subject"`
	Resource Resource        `json:"resource"`
	Action   string          `json:"action"`
	Context  EvaluationContext `json:"context"`
}

// Subject represents the entity requesting access
type Subject struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"` // user, service, api_key
	Attributes map[string]string `json:"attributes"`
	Roles      []string          `json:"roles"`
	Groups     []string          `json:"groups"`
	Authenticated bool           `json:"authenticated"`
}

// Resource represents the target resource
type Resource struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name,omitempty"`
	Owner      string            `json:"owner,omitempty"`
	Path       string            `json:"path,omitempty"`
	Attributes map[string]string `json:"attributes"`
	Tags       []string          `json:"tags"`
}

// EvaluationContext provides additional context for evaluation
type EvaluationContext struct {
	IPAddress     string            `json:"ip_address,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	Time          time.Time         `json:"time,omitempty"`
	Environment   string            `json:"environment,omitempty"` // dev, staging, prod
	DeviceID      string            `json:"device_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
	Location      string            `json:"location,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// ZTPolicyResult is the result of policy evaluation
type ZTPolicyResult struct {
	Allowed     bool              `json:"allowed"`
	Effect      PolicyEffect      `json:"effect"`
	MatchedPolicies []MatchedPolicy `json:"matched_policies,omitempty"`
	DeniedBy    []string          `json:"denied_by,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	EvaluatedAt time.Time         `json:"evaluated_at"`
	Duration    time.Duration     `json:"duration"`
}

// MatchedPolicy represents a policy that matched during evaluation
type MatchedPolicy struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Version    int    `json:"version"`
	Effect     PolicyEffect `json:"effect"`
	Priority   int    `json:"priority"`
}

// ZTPolicyEvaluator evaluates Zero Trust policies
type ZTPolicyEvaluator struct {
	policies []ZTPolicy
}

// NewZTPolicyEvaluator creates a new policy evaluator
func NewZTPolicyEvaluator() *ZTPolicyEvaluator {
	return &ZTPolicyEvaluator{
		policies: make([]ZTPolicy, 0),
	}
}

// AddPolicy adds a policy to the evaluator
func (e *ZTPolicyEvaluator) AddPolicy(policy ZTPolicy) {
	e.policies = append(e.policies, policy)
}

// SetPolicies replaces all policies with the given set
func (e *ZTPolicyEvaluator) SetPolicies(policies []ZTPolicy) {
	e.policies = policies
}

// GetPolicies returns all policies
func (e *ZTPolicyEvaluator) GetPolicies() []ZTPolicy {
	return e.policies
}

// Evaluate evaluates the input against all enabled policies
// Zero Trust default: deny all, unless explicitly allowed
func (e *ZTPolicyEvaluator) Evaluate(input ZTPolicyInput) *ZTPolicyResult {
	start := time.Now()
	result := &ZTPolicyResult{
		Allowed:         false,
		Effect:          EffectDeny,
		MatchedPolicies: make([]MatchedPolicy, 0),
		DeniedBy:        make([]string, 0),
		EvaluatedAt:     start,
	}

	// Sort policies by priority (higher priority first)
	sortedPolicies := e.sortByPriority(e.policies)

	// First pass: check for explicit denies (higher priority)
	for _, policy := range sortedPolicies {
		if !policy.Enabled {
			continue
		}

		matched := e.evaluateConditions(policy.Conditions, input)
		if matched {
			matchedPolicy := MatchedPolicy{
				PolicyID:   policy.ID,
				PolicyName: policy.Name,
				Version:    policy.Version,
				Effect:     policy.Effect,
				Priority:   policy.Priority,
			}
			result.MatchedPolicies = append(result.MatchedPolicies, matchedPolicy)

			if policy.Effect == EffectDeny {
				result.Allowed = false
				result.Effect = EffectDeny
				result.DeniedBy = append(result.DeniedBy, policy.Name)
				result.Reason = fmt.Sprintf("Access denied by policy: %s", policy.Name)
				result.Duration = time.Since(start)
				return result
			}
		}
	}

	// Second pass: check for allows
	// In Zero Trust, explicit allows override the default deny
	allowFound := false
	for _, matched := range result.MatchedPolicies {
		if matched.Effect == EffectAllow {
			allowFound = true
			break
		}
	}

	if allowFound {
		result.Allowed = true
		result.Effect = EffectAllow
		result.Reason = "Access granted by matched policies"
	} else {
		result.Reason = "Access denied: no matching allow policy (Zero Trust default)"
	}

	result.Duration = time.Since(start)
	return result
}

// EvaluateSingle evaluates against a single policy
func (e *ZTPolicyEvaluator) EvaluateSingle(policyID string, input ZTPolicyInput) (*ZTPolicyResult, error) {
	for _, policy := range e.policies {
		if policy.ID == policyID {
			start := time.Now()
			matched := e.evaluateConditions(policy.Conditions, input)

			return &ZTPolicyResult{
				Allowed:     matched && policy.Effect == EffectAllow,
				Effect:      policy.Effect,
				MatchedPolicies: []MatchedPolicy{{
					PolicyID:   policy.ID,
					PolicyName: policy.Name,
					Version:    policy.Version,
					Effect:     policy.Effect,
					Priority:   policy.Priority,
				}},
				Reason:      fmt.Sprintf("Policy %s evaluated", policy.Name),
				EvaluatedAt: start,
				Duration:    time.Since(start),
			}, nil
		}
	}
	return nil, fmt.Errorf("policy not found: %s", policyID)
}

// evaluateConditions evaluates a condition group against input
func (e *ZTPolicyEvaluator) evaluateConditions(group ConditionGroup, input ZTPolicyInput) bool {
	if group.Operator == OpNot {
		// NOT operator: negate the result of the first condition or group
		if len(group.Conditions) == 1 && len(group.Groups) == 0 {
			return !e.evaluateCondition(group.Conditions[0], input)
		}
		if len(group.Groups) == 1 && len(group.Conditions) == 0 {
			return !e.evaluateConditions(group.Groups[0], input)
		}
		// If multiple items in NOT, treat as NAND
		for _, cond := range group.Conditions {
			if e.evaluateCondition(cond, input) {
				return false
			}
		}
		for _, g := range group.Groups {
			if e.evaluateConditions(g, input) {
				return false
			}
		}
		return true
	}

	results := make([]bool, 0)

	// Evaluate all conditions
	for _, condition := range group.Conditions {
		result := e.evaluateCondition(condition, input)
		if condition.Negated {
			result = !result
		}
		results = append(results, result)
	}

	// Evaluate nested groups
	for _, nestedGroup := range group.Groups {
		result := e.evaluateConditions(nestedGroup, input)
		results = append(results, result)
	}

	// Apply operator
	switch group.Operator {
	case OpAnd:
		for _, r := range results {
			if !r {
				return false
			}
		}
		return len(results) > 0
	case OpOr:
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// evaluateCondition evaluates a single condition
func (e *ZTPolicyEvaluator) evaluateCondition(condition Condition, input ZTPolicyInput) bool {
	// SECURITY: Validate field name against allowlist to prevent injection attacks
	if !isFieldAllowed(condition.Field) {
		// Reject invalid fields rather than evaluating them
		return false
	}

	fieldValue := e.getFieldValue(condition.Field, input)
	if fieldValue == nil {
		return false
	}

	switch condition.Operator {
	case OpEquals:
		return e.compareEquals(fieldValue, condition.Value)
	case OpNotEquals:
		return !e.compareEquals(fieldValue, condition.Value)
	case OpContains:
		return e.compareContains(fieldValue, condition.Value)
	case OpNotContains:
		return !e.compareContains(fieldValue, condition.Value)
	case OpStartsWith:
		return e.compareStartsWith(fieldValue, condition.Value)
	case OpEndsWith:
		return e.compareEndsWith(fieldValue, condition.Value)
	case OpIn:
		return e.compareIn(fieldValue, condition.Value)
	case OpNotIn:
		return !e.compareIn(fieldValue, condition.Value)
	case OpGreaterThan:
		return eCompareNumeric(fieldValue, condition.Value, 1)
	case OpLessThan:
		return eCompareNumeric(fieldValue, condition.Value, -1)
	case OpIPInRange:
		return e.compareIPInRange(fieldValue, condition.Value)
	case OpTimeInRange:
		return e.compareTimeInRange(fieldValue, condition.Value, input.Context.Time)
	case OpDayOfWeek:
		return e.compareDayOfWeek(fieldValue, condition.Value, input.Context.Time)
	case OpHasRole:
		return e.compareHasRole(input.Subject.Roles, condition.Value)
	case OpHasGroup:
		return e.compareHasGroup(input.Subject.Groups, condition.Value)
	case OpHasAttribute:
		_, exists := input.Subject.Attributes[fmt.Sprint(condition.Value)]
		return exists
	case OpDeviceTrusted:
		return e.compareDeviceTrusted(input.Context, condition.Value)
	case OpLocationMatch:
		return e.compareLocation(input.Context, condition.Value)
	default:
		return false
	}
}

// getFieldValue extracts the value from input based on field path
// Supports: user.id, user.roles, resource.type, resource.attributes.key, context.ip, etc.
func (e *ZTPolicyEvaluator) getFieldValue(field string, input ZTPolicyInput) interface{} {
	parts := strings.Split(field, ".")

	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "subject", "user":
		return e.getSubjectValue(parts[1:], input.Subject)
	case "resource":
		return e.getResourceValue(parts[1:], input.Resource)
	case "context":
		return e.getContextValue(parts[1:], input.Context)
	case "action":
		if len(parts) == 1 {
			return input.Action
		}
		return nil
	default:
		return nil
	}
}

func (e *ZTPolicyEvaluator) getSubjectValue(parts []string, subject Subject) interface{} {
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "id":
		return subject.ID
	case "type":
		return subject.Type
	case "authenticated":
		return subject.Authenticated
	case "roles":
		if len(parts) == 1 {
			return subject.Roles
		}
		// roles[index] or specific role check
		return nil
	case "groups":
		if len(parts) == 1 {
			return subject.Groups
		}
		return nil
	case "attributes":
		if len(parts) == 2 {
			return subject.Attributes[parts[1]]
		}
		return subject.Attributes
	default:
		// Check in attributes
		return subject.Attributes[parts[0]]
	}
}

func (e *ZTPolicyEvaluator) getResourceValue(parts []string, resource Resource) interface{} {
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "id":
		return resource.ID
	case "type":
		return resource.Type
	case "name":
		return resource.Name
	case "owner":
		return resource.Owner
	case "path":
		return resource.Path
	case "tags":
		return resource.Tags
	case "attributes":
		if len(parts) == 2 {
			return resource.Attributes[parts[1]]
		}
		return resource.Attributes
	default:
		return resource.Attributes[parts[0]]
	}
}

func (e *ZTPolicyEvaluator) getContextValue(parts []string, context EvaluationContext) interface{} {
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "ip", "ip_address":
		return context.IPAddress
	case "user_agent":
		return context.UserAgent
	case "time":
		return context.Time
	case "environment":
		return context.Environment
	case "device_id":
		return context.DeviceID
	case "session_id":
		return context.SessionID
	case "request_id":
		return context.RequestID
	case "location":
		return context.Location
	case "attributes":
		if len(parts) == 2 {
			return context.Attributes[parts[1]]
		}
		return context.Attributes
	default:
		return context.Attributes[parts[0]]
	}
}

// Comparison functions

func (e *ZTPolicyEvaluator) compareEquals(fieldValue, conditionValue interface{}) bool {
	return fmt.Sprint(fieldValue) == fmt.Sprint(conditionValue)
}

func (e *ZTPolicyEvaluator) compareContains(fieldValue, conditionValue interface{}) bool {
	fieldStr := fmt.Sprint(fieldValue)
	conditionStr := fmt.Sprint(conditionValue)
	return strings.Contains(fieldStr, conditionStr)
}

func (e *ZTPolicyEvaluator) compareStartsWith(fieldValue, conditionValue interface{}) bool {
	fieldStr := fmt.Sprint(fieldValue)
	conditionStr := fmt.Sprint(conditionValue)
	return strings.HasPrefix(fieldStr, conditionStr)
}

func (e *ZTPolicyEvaluator) compareEndsWith(fieldValue, conditionValue interface{}) bool {
	fieldStr := fmt.Sprint(fieldValue)
	conditionStr := fmt.Sprint(conditionValue)
	return strings.HasSuffix(fieldStr, conditionStr)
}

func (e *ZTPolicyEvaluator) compareIn(fieldValue, conditionValue interface{}) bool {
	fieldStr := fmt.Sprint(fieldValue)

	// Parse condition value as JSON array
	arrBytes, err := json.Marshal(conditionValue)
	if err != nil {
		return false
	}

	var values []interface{}
	if err := json.Unmarshal(arrBytes, &values); err != nil {
		// If not an array, check if it's a comma-separated string
		strValue := fmt.Sprint(conditionValue)
		parts := strings.Split(strValue, ",")
		for _, part := range parts {
			if strings.TrimSpace(part) == fieldStr {
				return true
			}
		}
		return false
	}

	for _, v := range values {
		if fmt.Sprint(v) == fieldStr {
			return true
		}
	}
	return false
}

func eCompareNumeric(fieldValue, conditionValue interface{}, direction int) bool {
	// direction: 1 for greater than, -1 for less than
	var fieldFloat, condFloat float64

	switch v := fieldValue.(type) {
	case float64:
		fieldFloat = v
	case int:
		fieldFloat = float64(v)
	case int64:
		fieldFloat = float64(v)
	case string:
		// Try parsing as float
		if _, err := fmt.Sscanf(v, "%f", &fieldFloat); err != nil {
			return false
		}
	default:
		return false
	}

	switch v := conditionValue.(type) {
	case float64:
		condFloat = v
	case int:
		condFloat = float64(v)
	case int64:
		condFloat = float64(v)
	case string:
		if _, err := fmt.Sscanf(v, "%f", &condFloat); err != nil {
			return false
		}
	default:
		return false
	}

	if direction == 1 {
		return fieldFloat > condFloat
	}
	return fieldFloat < condFloat
}

func (e *ZTPolicyEvaluator) compareIPInRange(fieldValue, conditionValue interface{}) bool {
	ipStr := fmt.Sprint(fieldValue)
	cidrStr := fmt.Sprint(conditionValue)

	// Check if IP is in CIDR range
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	return ipNet.Contains(ip)
}

func (e *ZTPolicyEvaluator) compareTimeInRange(fieldValue, conditionValue interface{}, currentTime time.Time) bool {
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	// Parse condition value as time range JSON: {"start": "09:00", "end": "17:00"}
	data, err := json.Marshal(conditionValue)
	if err != nil {
		return false
	}

	var timeRange struct {
		Start string `json:"start"`
		End   string `json:"end"`
		Timezone string `json:"timezone,omitempty"`
	}
	if err := json.Unmarshal(data, &timeRange); err != nil {
		return false
	}

	startTime, err := time.Parse("15:04", timeRange.Start)
	if err != nil {
		return false
	}
	endTime, err := time.Parse("15:04", timeRange.End)
	if err != nil {
		return false
	}

	currentHourMin := currentTime.Format("15:04")
	currentTimeParsed, _ := time.Parse("15:04", currentHourMin)

	// Handle overnight ranges (e.g., 22:00 to 06:00)
	if endTime.Before(startTime) {
		return !currentTimeParsed.Before(startTime) || currentTimeParsed.Before(endTime)
	}

	// Use !Before for inclusive start (>=) and Before for exclusive end (<)
	return !currentTimeParsed.Before(startTime) && currentTimeParsed.Before(endTime)
}

func (e *ZTPolicyEvaluator) compareDayOfWeek(fieldValue, conditionValue interface{}, currentTime time.Time) bool {
	if currentTime.IsZero() {
		currentTime = time.Now()
	}

	// fieldValue might be empty, we use current time
	dayOfWeek := int(currentTime.Weekday())

	// conditionValue can be:
	// - Single integer: 0 (Sunday) to 6 (Saturday)
	// - Array of integers
	// - String name: "Monday", "Tuesday", etc.

	switch v := conditionValue.(type) {
	case float64:
		return dayOfWeek == int(v)
	case int:
		return dayOfWeek == v
	case string:
		// Parse day name
		targetDay := parseDayOfWeek(v)
		return targetDay == dayOfWeek
	case []interface{}:
		for _, item := range v {
			if day, ok := item.(float64); ok {
				if dayOfWeek == int(day) {
					return true
				}
			}
			if dayStr, ok := item.(string); ok {
				if parseDayOfWeek(dayStr) == dayOfWeek {
					return true
				}
			}
		}
		return false
	case []int:
		for _, day := range v {
			if dayOfWeek == day {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func parseDayOfWeek(day string) int {
	days := map[string]int{
		"sunday":    0,
		"monday":    1,
		"tuesday":   2,
		"wednesday": 3,
		"thursday":  4,
		"friday":    5,
		"saturday":  6,
	}
	lowerDay := strings.ToLower(strings.TrimSpace(day))
	if d, ok := days[lowerDay]; ok {
		return d
	}
	return -1
}

func (e *ZTPolicyEvaluator) compareHasRole(roles []string, conditionValue interface{}) bool {
	targetRole := fmt.Sprint(conditionValue)
	for _, role := range roles {
		if role == targetRole {
			return true
		}
	}
	return false
}

func (e *ZTPolicyEvaluator) compareHasGroup(groups []string, conditionValue interface{}) bool {
	targetGroup := fmt.Sprint(conditionValue)
	for _, group := range groups {
		if group == targetGroup {
			return true
		}
	}
	return false
}

func (e *ZTPolicyEvaluator) compareDeviceTrusted(context EvaluationContext, conditionValue interface{}) bool {
	// Check if device is in trusted devices list
	// This would typically query a device trust service
	if context.DeviceID == "" {
		return false
	}

	// conditionValue can be a list of trusted device IDs
	switch v := conditionValue.(type) {
	case []interface{}:
		for _, item := range v {
			if fmt.Sprint(item) == context.DeviceID {
				return true
			}
		}
		return false
	case string:
		return context.DeviceID == v
	default:
		// Check context attributes for device_trusted flag
		if trusted, ok := context.Attributes["device_trusted"]; ok {
			return strings.ToLower(trusted) == "true"
		}
		return false
	}
}

func (e *ZTPolicyEvaluator) compareLocation(context EvaluationContext, conditionValue interface{}) bool {
	location := context.Location
	if location == "" {
		return false
	}

	targetLocation := fmt.Sprint(conditionValue)
	return strings.EqualFold(location, targetLocation)
}

// sortByPriority sorts policies by priority (descending) and then by creation date
func (e *ZTPolicyEvaluator) sortByPriority(policies []ZTPolicy) []ZTPolicy {
	sorted := make([]ZTPolicy, len(policies))
	copy(sorted, policies)

	// Simple bubble sort (for small policy lists)
	n := len(sorted)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if sorted[j].Priority < sorted[j+1].Priority {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}
	return sorted
}

// NewZTPolicy creates a new policy with generated ID
func NewZTPolicy(name, description string, effect PolicyEffect, conditions ConditionGroup, priority int) ZTPolicy {
	return ZTPolicy{
		ID:         uuid.New().String(),
		Name:       name,
		Description: description,
		Effect:     effect,
		Conditions: conditions,
		Priority:   priority,
		Enabled:    true,
		Version:    1,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
}

// PolicyVersion represents a versioned policy for audit trail
type PolicyVersion struct {
	ID           string          `json:"id"`
	PolicyID     string          `json:"policy_id"`
	Version      int             `json:"version"`
	PolicyData   json.RawMessage `json:"policy_data"`
	ChangeType   string          `json:"change_type"` // created, updated, deleted, enabled, disabled
	ChangedBy    string          `json:"changed_by"`
	ChangeReason string          `json:"change_reason,omitempty"`
	ChangedAt    time.Time       `json:"changed_at"`
}
