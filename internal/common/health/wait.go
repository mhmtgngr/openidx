package health

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// WaitForDependency probes `probe` up to `attempts` times, `interval` apart, returning nil on
// the first success and the last error if all attempts fail. Logs each failed attempt. Respects
// ctx cancellation between attempts.
func WaitForDependency(ctx context.Context, log *zap.Logger, name string, attempts int, interval time.Duration, probe func(context.Context) error) error {
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for i := 1; i <= attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = probe(ctx)
		if last == nil {
			if i > 1 && log != nil {
				log.Info("dependency ready", zap.String("dependency", name), zap.Int("attempt", i))
			}
			return nil
		}
		if log != nil {
			log.Warn("dependency not ready, retrying",
				zap.String("dependency", name), zap.Int("attempt", i), zap.Int("max", attempts), zap.Error(last))
		}
		if i < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}
	return fmt.Errorf("dependency %q not ready after %d attempts: %w", name, attempts, last)
}

// ProbeHTTP returns a probe that GETs url and requires a 200 OK response to be considered
// healthy. Uses the passed ctx for cancellation with a short per-attempt timeout.
func ProbeHTTP(url string, timeout time.Duration) func(context.Context) error {
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
		}
		return nil
	}
}

// ProbeOPA returns a probe for an OPA server's health endpoint (opaURL + "/health").
func ProbeOPA(opaURL string, timeout time.Duration) func(context.Context) error {
	return ProbeHTTP(strings.TrimRight(opaURL, "/")+"/health", timeout)
}
