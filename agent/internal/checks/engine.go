package checks

import (
	"context"
	"fmt"
	"time"
)

// EngineResult wraps a CheckResult with metadata about how the check was
// configured and when it ran.
type EngineResult struct {
	CheckType string
	Severity  string
	Result    *CheckResult
	RanAt     time.Time
}

// Engine executes checks looked up from a Registry.
type Engine struct {
	registry *Registry
}

// NewEngine returns an Engine backed by registry.
func NewEngine(registry *Registry) *Engine {
	return &Engine{registry: registry}
}

// RunChecks iterates configs, resolves each check type from the registry, runs
// it, and returns the collected results. Configs that reference an unregistered
// check type receive a StatusError result.
func (e *Engine) RunChecks(ctx context.Context, configs []CheckConfig) []EngineResult {
	results := make([]EngineResult, 0, len(configs))

	for _, cfg := range configs {
		ranAt := time.Now()

		check, ok := e.registry.Get(cfg.Type)
		if !ok {
			results = append(results, EngineResult{
				CheckType: cfg.Type,
				Severity:  cfg.Severity,
				Result: &CheckResult{
					Status:  StatusError,
					Message: fmt.Sprintf("unknown check type: %s", cfg.Type),
				},
				RanAt: ranAt,
			})
			continue
		}

		result := check.Run(ctx, cfg.Params)

		results = append(results, EngineResult{
			CheckType: cfg.Type,
			Severity:  cfg.Severity,
			Result:    result,
			RanAt:     ranAt,
		})
	}

	return results
}
