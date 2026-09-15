// Package main is the entry point for the Event Relay.
//
// THE PROCESS THAT MAKES THE OUTBOX LIVE. Tasks 3.1a and 3.1b built the outbox
// table, the publisher and the relay; task 3.2 built the sink. Until this
// binary existed, none of it ran anywhere -- and the plan said so in as many
// words, because a table nothing writes to differs from a package nothing
// imports only by intention. This is the process that closes that gap.
//
// WHAT IT DOES, AND WHAT IT DELIBERATELY DOES NOT.
//
//   - It drains the outbox into NATS JetStream and marks what the broker
//     accepted, in one transaction per batch. The relay owns that logic; this
//     file only supplies it with a database, a sink and a signal to stop.
//   - It does NOT elect a leader for the drain, and that is not an omission:
//     `FOR UPDATE SKIP LOCKED` is the coordination, so any number of these run
//     safely and none of them can claim a row another holds. The relay's own
//     comment explains why a lease would be a worse trade.
//   - The retention sweep IS coordinated, because a sweep is not a claim: every
//     replica would otherwise delete its own batch of the same rows on the same
//     tick. leader.RunPeriodic gates it, which is the shape the sweeps census
//     recognises.
package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	goredis "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/openidx/openidx/internal/common/config"
	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/internal/common/events"
	"github.com/openidx/openidx/internal/common/leader"
	"github.com/openidx/openidx/internal/common/logger"
	"github.com/openidx/openidx/internal/metrics"
	"github.com/openidx/openidx/internal/server"
)

var (
	Version    = "dev"
	BuildTime  = "unknown"
	CommitHash = "unknown"
)

// sweepInterval is how often the retention sweep runs when it is on at all.
// Hourly, because the thing it removes is a receipt whose value decays over
// days -- a tighter tick would only compete with the drain for the same table.
const sweepInterval = time.Hour

func main() {
	log := logger.New()
	defer log.Sync()

	log.Info("Starting Event Relay",
		zap.String("version", Version),
		zap.String("build_time", BuildTime),
		zap.String("commit", CommitHash),
	)

	cfg, err := config.Load("event-relay")
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}
	if err := logger.SetLevel(cfg.LogLevel); err != nil {
		log.Fatal("Invalid log level", zap.Error(err))
	}
	if err := config.ValidateProductionConfig(cfg, log); err != nil {
		log.Fatal("Production security validation failed", zap.Error(err))
	}
	cfg.LogSecurityWarnings(log)

	// REFUSE TO START WITHOUT A BROKER, rather than starting and failing every
	// publish. A relay with no sink looks healthy from outside: it claims rows,
	// cannot deliver them, rolls back, and claims them again. Nothing is lost --
	// the outbox is built for exactly that -- but nothing is delivered either,
	// and the only place the failure is visible is the table, which is the last
	// place anyone looks. Dying at boot is the loud version of the same fact.
	if cfg.NATSURL == "" {
		log.Fatal("NATS_URL is empty: the relay has no sink. A relay with no broker drains nothing and says nothing; set NATS_URL, or do not run this process.")
	}

	database.SetRLSMode(database.ParseRLSMode(cfg.RLSMode))

	db, err := database.NewPostgres(cfg.DatabaseURL, database.PostgresTLSConfig{
		SSLMode:     cfg.DatabaseSSLMode,
		SSLRootCert: cfg.DatabaseSSLRootCert,
		SSLCert:     cfg.DatabaseSSLCert,
		SSLKey:      cfg.DatabaseSSLKey,
	})
	if err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer db.Close()
	metrics.NewTracedPool(db.Pool.Raw(), "event-relay").StartPoolStatsCollector(context.Background())

	nc, err := connectNATS(cfg, log)
	if err != nil {
		log.Fatal("Failed to connect to NATS", zap.Error(err))
	}
	defer nc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink, err := events.NewNATSSink(ctx, nc, events.NATSSinkConfig{
		Stream: cfg.EventStream,
		Prefix: cfg.EventSubjectPrefix,
	})
	if err != nil {
		// Creating the stream is also the first proof that the credentials this
		// process holds may actually publish: the JetStream API call goes through
		// the same permissions as every event will.
		log.Fatal("Failed to open the event stream", zap.Error(err),
			zap.String("stream", cfg.EventStream),
			zap.String("subject_prefix", cfg.EventSubjectPrefix))
	}

	relay := events.NewRelay(db, sink, events.RelayConfig{}, log)
	go relay.Run(ctx)
	log.Info("Outbox relay draining",
		zap.String("stream", cfg.EventStream),
		zap.String("subject_prefix", cfg.EventSubjectPrefix))

	startRetentionSweep(ctx, cfg, relay, log)

	// A health endpoint, and a deliberately shallow one. This process has no
	// request path, so "ready" here means the process is up -- the honest
	// signals for whether it is DELIVERING are the outbox backlog and the
	// relay's own metrics, not a 200 from a port nobody routes to.
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","service":"event-relay"}`))
	})
	// promhttp directly rather than metrics.Handler(): that one returns a
	// gin.HandlerFunc, because every other service in this tree is a gin app
	// and this one has no routes to be. Same default registry, so the relay's
	// counters and the pool gauges above are the same series they would be
	// anywhere else.
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health listener stopped", zap.Error(err))
		}
	}()

	graceful := server.New(server.Config{Server: srv, Logger: log})
	// Stopping the drain BEFORE the pools close is what makes a shutdown clean
	// rather than a burst of errors: the relay holds a transaction across each
	// publish, and cancelling lets that transaction roll back -- which unlocks
	// the rows for the next replica instead of leaving them to a lock timeout.
	graceful.AddShutdownFunc("outbox-relay", func(context.Context) error {
		cancel()
		return nil
	})
	graceful.Start()
}

func connectNATS(cfg *config.Config, log *zap.Logger) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("openidx-event-relay"),
		// Reconnect forever. The relay has nothing to fall back to and nothing
		// to lose by waiting: unpublished rows stay in the outbox, so a broker
		// outage is a pause, not a loss -- and a process that exits on a
		// reconnect limit turns that pause into a crash loop.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("NATS disconnected; the outbox holds the backlog until it returns", zap.Error(err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("NATS reconnected", zap.String("url", c.ConnectedUrl()))
		}),
	}
	if cfg.NATSUser != "" {
		opts = append(opts, nats.UserInfo(cfg.NATSUser, cfg.NATSPassword))
	}
	return nats.Connect(cfg.NATSURL, opts...)
}

// startRetentionSweep ages out delivered rows, leader-gated, when it is on.
//
// Zero hours means off, and off is the default: a delivered row is a receipt,
// and the first question after an incident is "was this event published, and
// when". Deleting that by default would answer a question nobody asked at the
// cost of the one they will.
func startRetentionSweep(ctx context.Context, cfg *config.Config, relay *events.Relay, log *zap.Logger) {
	if cfg.OutboxKeepForHours <= 0 {
		log.Info("Outbox retention sweep is off; delivered rows are kept until OUTBOX_KEEP_FOR_HOURS is set")
		return
	}
	keepFor := time.Duration(cfg.OutboxKeepForHours) * time.Hour

	var rdb *goredis.Client
	if redisClient, err := database.NewRedisFromConfig(database.RedisConfig{
		URL:                cfg.RedisURL,
		SentinelEnabled:    cfg.RedisSentinelEnabled,
		SentinelMasterName: cfg.RedisSentinelMasterName,
		SentinelAddresses:  cfg.GetRedisSentinelAddresses(),
		SentinelPassword:   cfg.RedisSentinelPassword,
		Password:           cfg.GetRedisPassword(),
		TLSEnabled:         cfg.RedisTLSEnabled,
		TLSCACert:          cfg.RedisTLSCACert,
		TLSCert:            cfg.RedisTLSCert,
		TLSKey:             cfg.RedisTLSKey,
		TLSSkipVerify:      cfg.RedisTLSSkipVerify,
	}); err != nil {
		// Without Redis, leader.IsLeaderForTick treats this as a single
		// instance and every replica sweeps. That is safe -- the DELETE is
		// bounded and idempotent -- and it is wasteful, so it is said out loud
		// rather than discovered in a query plan.
		log.Warn("Redis unavailable; the retention sweep runs in every replica instead of one", zap.Error(err))
	} else {
		rdb = redisClient.Client
	}

	leader.RunPeriodic(ctx, rdb, log, "outbox-retention", sweepInterval, func(ctx context.Context) {
		deleted, err := relay.SweepPublished(ctx, events.SweepConfig{KeepFor: keepFor})
		if err != nil {
			log.Warn("outbox retention sweep failed", zap.Error(err))
			return
		}
		if deleted > 0 {
			log.Info("outbox retention sweep removed delivered rows",
				zap.Int64("deleted", deleted),
				zap.Duration("keep_for", keepFor))
		}
	})
}
