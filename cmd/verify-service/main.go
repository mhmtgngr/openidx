// Package main is the entry point for the Verify Service: the token-verification
// tier of the plane split (ADR-2).
//
// THE POINT OF THIS PROCESS IS WHAT IT CANNOT DO. It has no database pool, no
// client registry and no session store; the guard in main_test.go fails the
// build if `github.com/jackc/pgx` ever appears in its import graph, and that
// test is the feature. Everything else here is a small HTTP server.
//
// Two dependencies had to be split before this binary could exist, and both
// were the same shape -- a package that mixes the plane that reads the database
// with the plane that does not:
//
//   - internal/common/middleware held the JWKS cache next to PermissionResolver
//     and RequireFreshMFA, so a driver came along with every Auth() call. The
//     verification half now lives in internal/common/jwksverify, which this
//     imports; middleware calls the same package, so there is still one cache.
//   - internal/metrics reaches pgx for its pool collector, so /metrics here is
//     promhttp directly. Same default registry, so jwksverify's counters are
//     the same series they are in every other service.
//
// internal/common/database is the third instance and is NOT split: this process
// needs no Redis either, so it simply does not import it. A tier that needed a
// Redis client would today have to link a PostgreSQL driver to get one.
package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/server"
	"github.com/openidx/openidx/internal/verify"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

func main() {
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Verify Service",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	cfg, err := config.Load("verify-service")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}
	if err := logger.SetLevel(cfg.LogLevel); err != nil {
		log.Fatal("Invalid log level", zap.Error(err))
	}
	// THE PLATFORM PRODUCTION VALIDATOR IS DELIBERATELY NOT CALLED HERE, and
	// this is the plane split showing up a second time. config.ValidateProduction
	// refuses to start a production process without an access session secret, an
	// encryption key, a vault key-encryption key and an audit chain secret --
	// every one of which is material this tier exists in order NOT to hold. It
	// holds no sessions, encrypts nothing, has no vault and seals no audit
	// chain. Running it would force an operator to mount the most sensitive
	// secrets in the install into the one pod whose entire claim is that it
	// carries nothing, so that it can serve a public document.
	//
	// The checks it does need are below, and they run in EVERY environment
	// rather than only in production, because a verify tier with no issuer is
	// as useless in staging as it is in production.
	//
	// REFUSE TO START WITHOUT AN ISSUER. With no JWKS URL this process would
	// come up, pass its health check, and answer every key fetch with a 503 --
	// a tier that is up and serving nothing, which is the failure mode hardest
	// to see from outside. The one thing it needs is the one thing it is
	// pointed at.
	if cfg.OAuthJWKSURL == "" {
		log.Fatal("OAUTH_JWKS_URL is empty: the verify tier has no issuer to serve keys from. Set it, or do not run this process.")
	}

	svc := verify.New(cfg.OAuthJWKSURL, log)

	mux := http.NewServeMux()
	svc.RegisterRoutes(mux)

	// Shallow on purpose: "the process is up". Whether it can actually answer
	// depends on the issuer, and that belongs in the jwks_refresh_failures and
	// jwks_stale_seconds series, not in a readiness probe that would take the
	// whole tier out of rotation during an issuer blip -- exactly when the
	// serve-stale belt is keeping verification alive.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"verify-service"}`))
	})
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("verify listener stopped", zap.Error(err))
		}
	}()
	log.Info("Verify tier serving keys",
		zap.String("addr", cfg.ListenAddr()),
		zap.String("jwks_url", cfg.OAuthJWKSURL))

	server.New(server.Config{Server: srv, Logger: log}).Start()
}
