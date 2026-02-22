// Package governance provides policy evaluation and access governance functionality
package governance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/opa"
)

// compiledPolicy represents a compiled Rego policy ready for evaluation
type compiledPolicy struct {
	name      string
	module    *ast.Module
	compiled  *rego.Compiler
	policyRego string
	createdAt time.Time
}

// PolicyInput represents the input data for policy evaluation
type PolicyInput struct {
	User     PolicyUser     `json:"user"`
	Resource PolicyResource `json:"resource"`
	Action   string         `json:"action"`
	Context  PolicyContext  `json:"context,omitempty"`
}

// PolicyUser represents the user context in policy evaluation
type PolicyUser struct {
	ID            string            `json:"id"`
	Username      string            `json:"username"`
	Email         string            `json:"email,omitempty"`
	Roles         []string          `json:"roles"`
	Groups        []string          `json:"groups,omitempty"`
	TenantID      string            `json:"tenant_id,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	Authenticated bool              `json:"authenticated"`
}

// PolicyResource represents the resource being accessed
type PolicyResource struct {
	Type       string            `json:"type"`
	ID         string            `json:"id,omitempty"`
	Name       string            `json:"name,omitempty"`
	Owner      string            `json:"owner,omitempty"`
	Path       string            `json:"path,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
}

// PolicyContext represents additional context for policy evaluation
type PolicyContext struct {
	IPAddress     string            `json:"ip_address,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	Time          time.Time         `json:"time,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	RequestID     string            `json:"request_id,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	DeviceID      string            `json:"device_id,omitempty"`
	Location      string            `json:"location,omitempty"`
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Allow     bool     `json:"allow"`
	Denials   []string `json:"denials,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Score     float64  `json:"score,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
	Duration  time.Duration `json:"duration"`
}

// PolicyEvaluator evaluates access policies using OPA (Open Policy Agent)
type PolicyEvaluator struct {
	opaClient    *opa.Client
	logger       *zap.Logger
	policyCache  map[string]*compiledPolicy
	cacheMutex   sync.RWMutex
	store        storage.Store
	compiler     *rego.Compiler

	// Metrics
	evaluationDurationHist *metricHistogram
	evaluationTotalCounter *metricCounter
	cacheHitCounter        *metricCounter
	cacheMissCounter       *metricCounter
	policyReloadCounter    *metricCounter
	policyErrorCounter     *metricCounter

	// Configuration
	defaultPolicyTimeout time.Duration
	policyDir            string
	enabled              bool
}

// PolicyEvaluatorConfig configures the policy evaluator
type PolicyEvaluatorConfig struct {
	OPAURL               string
	PolicyDir            string
	DefaultPolicyTimeout time.Duration
	EnableMetrics        bool
	Logger               *zap.Logger
}

// metricHistogram is a simple histogram metric for tracking durations
type metricHistogram struct {
	name  string
	bucks []float64
	count int64
	sum   float64
}

func newMetricHistogram(name string, buckets []float64) *metricHistogram {
	return &metricHistogram{
		name:  name,
		bucks: buckets,
	}
}

func (m *metricHistogram) Observe(duration float64) {
	m.count++
	m.sum += duration
}

// metricCounter is a simple counter metric
type metricCounter struct {
	name  string
	count map[string]int64
	mutex sync.Mutex
}

func newMetricCounter(name string) *metricCounter {
	return &metricCounter{
		name:  name,
		count: make(map[string]int64),
	}
}

func (m *metricCounter) Inc(labels ...string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := m.key(labels...)
	m.count[key]++
}

func (m *metricCounter) key(labels ...string) string {
	key := m.name
	for _, l := range labels {
		key += ":" + l
	}
	return key
}

// NewPolicyEvaluator creates a new policy evaluator
func NewPolicyEvaluator(config PolicyEvaluatorConfig) *PolicyEvaluator {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.DefaultPolicyTimeout == 0 {
		config.DefaultPolicyTimeout = 5 * time.Second
	}

	pe := &PolicyEvaluator{
		opaClient:            opa.NewClient(config.OPAURL, config.Logger),
		logger:               config.Logger.With(zap.String("component", "policy_evaluator")),
		policyCache:          make(map[string]*compiledPolicy),
		store:                inmem.New(),
		defaultPolicyTimeout: config.DefaultPolicyTimeout,
		policyDir:            config.PolicyDir,
		enabled:              true,
	}

	if config.EnableMetrics {
		pe.evaluationDurationHist = newMetricHistogram(
			"openidx_policy_evaluation_duration_seconds",
			[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		)
		pe.evaluationTotalCounter = newMetricCounter("openidx_policy_evaluation_total")
		pe.cacheHitCounter = newMetricCounter("openidx_policy_cache_hits_total")
		pe.cacheMissCounter = newMetricCounter("openidx_policy_cache_misses_total")
		pe.policyReloadCounter = newMetricCounter("openidx_policy_reloads_total")
		pe.policyErrorCounter = newMetricCounter("openidx_policy_errors_total")
	}

	return pe
}

// EvaluatePolicy evaluates a policy against the provided input
func (pe *PolicyEvaluator) EvaluatePolicy(ctx context.Context, policyName string, input PolicyInput) (*PolicyResult, error) {
	start := time.Now()

	if pe.evaluationTotalCounter != nil {
		pe.evaluationTotalCounter.Inc(policyName)
	}

	result := &PolicyResult{
		EvaluatedAt: start,
	}

	// Check cache for compiled policy
	pe.cacheMutex.RLock()
	cachedPolicy, found := pe.policyCache[policyName]
	pe.cacheMutex.RUnlock()

	if !found {
		if pe.cacheMissCounter != nil {
			pe.cacheMissCounter.Inc()
		}
		return nil, fmt.Errorf("policy not found: %s", policyName)
	}

	if pe.cacheHitCounter != nil {
		pe.cacheHitCounter.Inc()
	}

	// Prepare query
	query := rego.Result{
		Exprs: []ast.Expression{
			ast.Call.Builder().Function(ast.Var("data")).Builtins(),
		},
	}

	// Create rego query for the specific policy entry point
	regoQuery := fmt.Sprintf("data.%s.allow", policyName)

	// Build rego evaluation
	r := rego.New(
		rego.Query(regoQuery),
		rego.Compiler(cachedPolicy.compiled),
		rego.Input(input),
		rego.Store(pe.store),
	)

	// Set timeout
	evalCtx, cancel := context.WithTimeout(ctx, pe.defaultPolicyTimeout)
	defer cancel()

	// Execute evaluation
	rs, err := r.Eval(evalCtx)
	if err != nil {
		if pe.policyErrorCounter != nil {
			pe.policyErrorCounter.Inc(policyName, "evaluation_error")
		}
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Parse results
	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		if allow, ok := rs[0].Expressions[0].Value.(bool); ok {
			result.Allow = allow
		}
	}

	// Query for denials
	denyQuery := fmt.Sprintf("data.%s.deny", policyName)
	rDeny := rego.New(
		rego.Query(denyQuery),
		rego.Compiler(cachedPolicy.compiled),
		rego.Input(input),
		rego.Store(pe.store),
	)

	denyResults, err := rDeny.Eval(evalCtx)
	if err == nil && len(denyResults) > 0 && len(denyResults[0].Expressions) > 0 {
		if denials, ok := denyResults[0].Expressions[0].Value.([]interface{}); ok {
			result.Denials = make([]string, 0, len(denials))
			for _, d := range denials {
				if denialStr, ok := d.(string); ok {
					result.Denials = append(result.Denials, denialStr)
				}
			}
		}
	}

	// Query for warnings
	warningQuery := fmt.Sprintf("data.%s.warnings", policyName)
	rWarn := rego.New(
		rego.Query(warningQuery),
		rego.Compiler(cachedPolicy.compiled),
		rego.Input(input),
		rego.Store(pe.store),
	)

	warnResults, err := rWarn.Eval(evalCtx)
	if err == nil && len(warnResults) > 0 && len(warnResults[0].Expressions) > 0 {
		if warnings, ok := warnResults[0].Expressions[0].Value.([]interface{}); ok {
			result.Warnings = make([]string, 0, len(warnings))
			for _, w := range warnings {
				if warnStr, ok := w.(string); ok {
					result.Warnings = append(result.Warnings, warnStr)
				}
			}
		}
	}

	// Calculate reason
	if !result.Allow && len(result.Denials) > 0 {
		result.Reason = result.Denials[0]
	} else if result.Allow {
		result.Reason = "Access granted by policy"
	}

	result.Duration = time.Since(start)

	if pe.evaluationDurationHist != nil {
		pe.evaluationDurationHist.Observe(result.Duration.Seconds())
	}

	pe.logger.Debug("Policy evaluation completed",
		zap.String("policy", policyName),
		zap.Bool("allow", result.Allow),
		zap.Duration("duration", result.Duration),
	)

	return result, nil
}

// EvaluatePolicyDefault evaluates using the default policy
func (pe *PolicyEvaluator) EvaluatePolicyDefault(ctx context.Context, input PolicyInput) (*PolicyResult, error) {
	return pe.EvaluatePolicy(ctx, "openidx", input)
}

// LoadPolicyFromBytes loads a policy from raw Rego content
func (pe *PolicyEvaluator) LoadPolicyFromBytes(policyName string, regoContent []byte) error {
	pe.logger.Info("Loading policy from bytes",
		zap.String("policy", policyName),
		zap.Int("size", len(regoContent)),
	)

	// Parse the module
	module, err := ast.ParseModule(policyName, string(regoContent))
	if err != nil {
		if pe.policyErrorCounter != nil {
			pe.policyErrorCounter.Inc(policyName, "parse_error")
		}
		return fmt.Errorf("parse policy module: %w", err)
	}

	// Create compiler
	compiler := ast.NewCompiler().WithEnablePrintStatements(true)

	// Compile the module
	if err := compiler.Compile(map[string]*ast.Module{policyName: module}); err != nil {
		if pe.policyErrorCounter != nil {
			pe.policyErrorCounter.Inc(policyName, "compile_error")
		}
		return fmt.Errorf("compile policy: %w", err)
	}

	// Store in cache
	pe.cacheMutex.Lock()
	defer pe.cacheMutex.Unlock()

	pe.policyCache[policyName] = &compiledPolicy{
		name:      policyName,
		module:    module,
		compiled:  compiler,
		policyRego: string(regoContent),
		createdAt: time.Now(),
	}

	pe.logger.Info("Policy loaded successfully",
		zap.String("policy", policyName),
		zap.Int("rules", len(module.Rules)),
	)

	return nil
}

// LoadPolicyFromFile loads a policy from a file
func (pe *PolicyEvaluator) LoadPolicyFromFile(policyPath string) error {
	pe.logger.Info("Loading policy from file", zap.String("path", policyPath))

	content, err := os.ReadFile(policyPath)
	if err != nil {
		if pe.policyErrorCounter != nil {
			pe.policyErrorCounter.Inc(policyPath, "read_error")
		}
		return fmt.Errorf("read policy file: %w", err)
	}

	// Extract policy name from filename
	policyName := filepath.Base(policyPath)
	policyName = policyName[:len(policyName)-len(filepath.Ext(policyName))]

	return pe.LoadPolicyFromBytes(policyName, content)
}

// LoadPoliciesFromDirectory loads all .rego files from a directory
func (pe *PolicyEvaluator) LoadPoliciesFromDirectory(dir string) error {
	pe.logger.Info("Loading policies from directory", zap.String("dir", dir))

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read directory: %w", err)
	}

	var loadErrors []error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) == ".rego" {
			policyPath := filepath.Join(dir, entry.Name())
			if err := pe.LoadPolicyFromFile(policyPath); err != nil {
				pe.logger.Warn("Failed to load policy",
					zap.String("path", policyPath),
					zap.Error(err),
				)
				loadErrors = append(loadErrors, err)
			}
		}
	}

	if len(loadErrors) > 0 {
		return fmt.Errorf("encountered %d errors loading policies", len(loadErrors))
	}

	return nil
}

// ReloadPolicies hot-reloads all policies from the configured directory
func (pe *PolicyEvaluator) ReloadPolicies(ctx context.Context) error {
	pe.logger.Info("Reloading policies")
	start := time.Now()

	if pe.policyReloadCounter != nil {
		pe.policyReloadCounter.Inc()
	}

	if pe.policyDir == "" {
		return fmt.Errorf("policy directory not configured")
	}

	// Clear existing cache
	pe.cacheMutex.Lock()
	pe.policyCache = make(map[string]*compiledPolicy)
	pe.cacheMutex.Unlock()

	// Reload all policies
	if err := pe.LoadPoliciesFromDirectory(pe.policyDir); err != nil {
		if pe.policyErrorCounter != nil {
			pe.policyErrorCounter.Inc("reload", "load_error")
		}
		return fmt.Errorf("reload policies: %w", err)
	}

	duration := time.Since(start)
	pe.logger.Info("Policies reloaded successfully",
		zap.Int("count", len(pe.policyCache)),
		zap.Duration("duration", duration),
	)

	return nil
}

// GetPolicyNames returns the names of all loaded policies
func (pe *PolicyEvaluator) GetPolicyNames() []string {
	pe.cacheMutex.RLock()
	defer pe.cacheMutex.RUnlock()

	names := make([]string, 0, len(pe.policyCache))
	for name := range pe.policyCache {
		names = append(names, name)
	}
	return names
}

// PolicyExists checks if a policy is loaded
func (pe *PolicyEvaluator) PolicyExists(policyName string) bool {
	pe.cacheMutex.RLock()
	defer pe.cacheMutex.RUnlock()

	_, exists := pe.policyCache[policyName]
	return exists
}

// RemovePolicy removes a policy from the cache
func (pe *PolicyEvaluator) RemovePolicy(policyName string) error {
	pe.cacheMutex.Lock()
	defer pe.cacheMutex.Unlock()

	if _, exists := pe.policyCache[policyName]; !exists {
		return fmt.Errorf("policy not found: %s", policyName)
	}

	delete(pe.policyCache, policyName)
	pe.logger.Info("Policy removed", zap.String("policy", policyName))
	return nil
}

// GetPolicyInfo returns information about a loaded policy
func (pe *PolicyEvaluator) GetPolicyInfo(policyName string) (*PolicyInfo, error) {
	pe.cacheMutex.RLock()
	defer pe.cacheMutex.RUnlock()

	policy, exists := pe.policyCache[policyName]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyName)
	}

	return &PolicyInfo{
		Name:      policy.name,
		CreatedAt: policy.createdAt,
		RuleCount: len(policy.module.Rules),
		Size:      len(policy.policyRego),
	}, nil
}

// PolicyInfo contains metadata about a loaded policy
type PolicyInfo struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	RuleCount int       `json:"rule_count"`
	Size      int       `json:"size"`
}

// GetMetrics returns current metrics
func (pe *PolicyEvaluator) GetMetrics() map[string]interface{} {
	pe.cacheMutex.RLock()
	defer pe.cacheMutex.RUnlock()

	metrics := map[string]interface{}{
		"policy_count":      len(pe.policyCache),
		"policy_names":      pe.GetPolicyNames(),
		"enabled":           pe.enabled,
		"default_timeout":   pe.defaultPolicyTimeout.String(),
	}

	if pe.evaluationTotalCounter != nil {
		pe.evaluationTotalCounter.mutex.Lock()
		metrics["evaluation_count"] = pe.evaluationTotalCounter.count
		pe.evaluationTotalCounter.mutex.Unlock()
	}

	if pe.cacheHitCounter != nil {
		pe.cacheHitCounter.mutex.Lock()
		metrics["cache_hits"] = pe.cacheHitCounter.count
		pe.cacheHitCounter.mutex.Unlock()
	}

	if pe.cacheMissCounter != nil {
		pe.cacheMissCounter.mutex.Lock()
		metrics["cache_misses"] = pe.cacheMissCounter.count
		pe.cacheMissCounter.mutex.Unlock()
	}

	return metrics
}

// Enable enables the policy evaluator
func (pe *PolicyEvaluator) Enable() {
	pe.enabled = true
	pe.logger.Info("Policy evaluator enabled")
}

// Disable disables the policy evaluator
func (pe *PolicyEvaluator) Disable() {
	pe.enabled = false
	pe.logger.Info("Policy evaluator disabled")
}

// IsEnabled returns whether the policy evaluator is enabled
func (pe *PolicyEvaluator) IsEnabled() bool {
	return pe.enabled
}
