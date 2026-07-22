// Package audit — SIEM forwarder.
//
// Streams the unified audit trail to an external SIEM (Splunk, QRadar, Sentinel,
// Elastic, etc.) so enterprise scorecards can check the "streams to <SIEM>?" box.
// It tails the audit_events table by a monotonic (timestamp,id) cursor and pushes
// each event to a configured destination in the operator's chosen wire format:
//
//   - syslog  — RFC 5424 syslog over TCP (optionally TLS), one framed message per event.
//   - cef     — ArcSight Common Event Format, wrapped in an RFC 5424 syslog frame.
//   - hec     — Splunk HTTP Event Collector (JSON over HTTPS with a token).
//
// Delivery is at-least-once: the cursor only advances past events that were
// acknowledged by the destination, and it is persisted so a restart resumes
// where it left off (no gaps, at the cost of possible re-delivery of the last
// batch — SIEMs dedupe on the event id we include).
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// SIEMConfig configures the forwarder. All fields come from environment
// variables (see SIEMConfigFromEnv). The forwarder is inert unless Enabled.
type SIEMConfig struct {
	Enabled bool
	// Format is one of "syslog", "cef", "hec".
	Format string
	// Endpoint is host:port for syslog/cef, or a full URL for hec
	// (e.g. https://splunk:8088/services/collector/event).
	Endpoint string
	// TLS enables TLS for the syslog/cef TCP connection (hec is always HTTPS
	// when the URL says so).
	TLS bool
	// InsecureSkipVerify skips TLS cert verification (self-signed dev SIEMs).
	InsecureSkipVerify bool
	// Token is the Splunk HEC authentication token (hec format only).
	Token string
	// Hostname is the syslog HOSTNAME field; defaults to the OS hostname.
	Hostname string
	// PollInterval is how often to check for new events. Defaults to 5s.
	PollInterval time.Duration
	// BatchSize bounds how many events are shipped per poll. Defaults to 200.
	BatchSize int
}

// SIEMConfigFromEnv builds the forwarder config from AUDIT_SIEM_* env vars.
func SIEMConfigFromEnv() SIEMConfig {
	c := SIEMConfig{
		Enabled:            strings.EqualFold(os.Getenv("AUDIT_SIEM_ENABLED"), "true"),
		Format:             strings.ToLower(strings.TrimSpace(os.Getenv("AUDIT_SIEM_FORMAT"))),
		Endpoint:           strings.TrimSpace(os.Getenv("AUDIT_SIEM_ENDPOINT")),
		TLS:                strings.EqualFold(os.Getenv("AUDIT_SIEM_TLS"), "true"),
		InsecureSkipVerify: strings.EqualFold(os.Getenv("AUDIT_SIEM_INSECURE_SKIP_VERIFY"), "true"),
		Token:              strings.TrimSpace(os.Getenv("AUDIT_SIEM_TOKEN")),
		Hostname:           strings.TrimSpace(os.Getenv("AUDIT_SIEM_HOSTNAME")),
	}
	if c.Format == "" {
		c.Format = "syslog"
	}
	if c.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			c.Hostname = h
		} else {
			c.Hostname = "openidx"
		}
	}
	c.PollInterval = 5 * time.Second
	if v := os.Getenv("AUDIT_SIEM_POLL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.PollInterval = time.Duration(n) * time.Second
		}
	}
	c.BatchSize = 200
	if v := os.Getenv("AUDIT_SIEM_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.BatchSize = n
		}
	}
	return c
}

// siemEvent is the subset of an audit_events row the forwarder ships.
type siemEvent struct {
	ID        string
	Timestamp time.Time
	OrgID     string
	ActorID   string
	ActorType string
	ActorIP   string
	TargetID  string
	Target    string
	EventType string
	Category  string
	Action    string
	Outcome   string
	Details   json.RawMessage
}

// siemSink delivers a batch of events, returning an error if the destination
// did not accept them (so the cursor does not advance).
type siemSink interface {
	deliver(events []siemEvent) error
	Close() error
}

// StartSIEMForwarder launches the forwarder as a background goroutine. It is a
// no-op when disabled or misconfigured (logged once). The cursor persists in a
// tiny siem_forward_cursor table so restarts resume without gaps.
func (s *Service) StartSIEMForwarder(ctx context.Context) {
	cfg := SIEMConfigFromEnv()
	if !cfg.Enabled {
		return
	}
	if cfg.Endpoint == "" {
		s.logger.Error("SIEM forwarder enabled but AUDIT_SIEM_ENDPOINT is empty; not starting")
		return
	}
	if cfg.Format != "syslog" && cfg.Format != "cef" && cfg.Format != "hec" {
		s.logger.Error("SIEM forwarder: unsupported AUDIT_SIEM_FORMAT (want syslog|cef|hec)",
			zap.String("format", cfg.Format))
		return
	}
	f := &siemForwarder{svc: s, cfg: cfg, logger: s.logger.With(zap.String("component", "siem-forwarder"))}
	if err := f.ensureCursorTable(orgctx.WithBypassRLS(ctx)); err != nil {
		s.logger.Error("SIEM forwarder: cursor table init failed; not starting", zap.Error(err))
		return
	}
	f.logger.Info("SIEM forwarder starting",
		zap.String("format", cfg.Format), zap.String("endpoint", cfg.Endpoint),
		zap.Duration("poll", cfg.PollInterval), zap.Int("batch", cfg.BatchSize))
	go f.run(orgctx.WithBypassRLS(ctx))
}

type siemForwarder struct {
	svc    *Service
	cfg    SIEMConfig
	logger *zap.Logger
	sink   siemSink
}

func (f *siemForwarder) run(ctx context.Context) {
	ticker := time.NewTicker(f.cfg.PollInterval)
	defer ticker.Stop()
	defer func() {
		if f.sink != nil {
			_ = f.sink.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := f.forwardBatch(ctx); err != nil {
				f.logger.Warn("SIEM forward batch failed; will retry", zap.Error(err))
				// Drop the sink so the next attempt reconnects (handles a SIEM
				// restart or a dropped TCP connection).
				if f.sink != nil {
					_ = f.sink.Close()
					f.sink = nil
				}
			}
		}
	}
}

// ensureCursorTable creates the single-row cursor table (idempotent).
func (f *siemForwarder) ensureCursorTable(ctx context.Context) error {
	_, err := f.svc.db.Pool.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS siem_forward_cursor (
            id            INT PRIMARY KEY DEFAULT 1,
            last_ts       TIMESTAMPTZ NOT NULL DEFAULT 'epoch',
            last_id       UUID,
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT siem_forward_cursor_singleton CHECK (id = 1)
        );
        INSERT INTO siem_forward_cursor (id) VALUES (1) ON CONFLICT (id) DO NOTHING;`)
	return err
}

// forwardBatch ships the next batch of events past the cursor and, on successful
// delivery, advances + persists the cursor.
func (f *siemForwarder) forwardBatch(ctx context.Context) error {
	var lastTS time.Time
	var lastID *string
	if err := f.svc.db.Pool.QueryRow(ctx,
		`SELECT last_ts, last_id FROM siem_forward_cursor WHERE id = 1`).
		Scan(&lastTS, &lastID); err != nil {
		return fmt.Errorf("read cursor: %w", err)
	}
	// Fetch events strictly after the cursor, ordered by (timestamp,id) so the
	// cursor is a total order. Using a row-value comparison keeps it index-friendly.
	lastIDArg := "00000000-0000-0000-0000-000000000000"
	if lastID != nil {
		lastIDArg = *lastID
	}
	rows, err := f.svc.db.Pool.Query(ctx, `
        SELECT id, timestamp, COALESCE(org_id::text,''), COALESCE(actor_id,''),
               COALESCE(actor_type,''), COALESCE(actor_ip,''), COALESCE(target_id,''),
               COALESCE(target_type,''), COALESCE(event_type,''), COALESCE(category,''),
               COALESCE(action,''), COALESCE(outcome,''), COALESCE(details,'{}'::jsonb)
          FROM audit_events
         WHERE (timestamp, id) > ($1, $2::uuid)
         ORDER BY timestamp ASC, id ASC
         LIMIT $3`, lastTS, lastIDArg, f.cfg.BatchSize)
	if err != nil {
		return fmt.Errorf("query events: %w", err)
	}
	var batch []siemEvent
	for rows.Next() {
		var e siemEvent
		var details []byte
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.OrgID, &e.ActorID, &e.ActorType,
			&e.ActorIP, &e.TargetID, &e.Target, &e.EventType, &e.Category, &e.Action,
			&e.Outcome, &details); err != nil {
			rows.Close()
			return fmt.Errorf("scan event: %w", err)
		}
		e.Details = json.RawMessage(details)
		batch = append(batch, e)
	}
	rows.Close()
	if len(batch) == 0 {
		return nil
	}

	if f.sink == nil {
		sink, err := f.newSink()
		if err != nil {
			return fmt.Errorf("connect sink: %w", err)
		}
		f.sink = sink
	}
	if err := f.sink.deliver(batch); err != nil {
		return fmt.Errorf("deliver: %w", err)
	}

	last := batch[len(batch)-1]
	if _, err := f.svc.db.Pool.Exec(ctx,
		`UPDATE siem_forward_cursor SET last_ts = $1, last_id = $2, updated_at = NOW() WHERE id = 1`,
		last.Timestamp, last.ID); err != nil {
		// Delivered but cursor not advanced: acceptable (at-least-once) — the
		// next poll re-delivers this batch, which SIEMs dedupe on event id.
		return fmt.Errorf("advance cursor: %w", err)
	}
	f.logger.Debug("SIEM batch forwarded", zap.Int("count", len(batch)))
	return nil
}

func (f *siemForwarder) newSink() (siemSink, error) {
	switch f.cfg.Format {
	case "hec":
		return newHECSink(f.cfg), nil
	default: // syslog / cef both use the TCP syslog framing
		return newSyslogSink(f.cfg)
	}
}
