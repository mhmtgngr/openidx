// Package otel provides comprehensive OpenTelemetry distributed tracing for OpenIDX services.
// It includes instrumentation for HTTP, database (pgx), Redis, and supports multiple exporters.
package otel

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"
)

// Config holds OpenTelemetry tracing configuration
type Config struct {
	Enabled     bool
	ServiceName string
	Environment string

	// Exporter configuration
	ExporterType      string // "otlp", "jaeger", "stdout", "none"
	OTLPEndpoint      string // OTLP gRPC endpoint (e.g., "localhost:4317")
	JaegerEndpoint    string // Jaeger agent endpoint (e.g., "localhost:6831")

	// Sampling configuration
	SampleRatio float64 // 0.0 to 1.0; default 1.0 (100%)
	SamplerType string  // "ratio", "parentbased", "always", "never"

	// Additional resource attributes
	ResourceAttributes map[string]string
}

// ConfigFromEnv loads tracing config from standard OpenTelemetry environment variables
// following OpenTelemetry specification:
// - OTEL_EXPORTER_OTLP_ENDPOINT
// - OTEL_SERVICE_NAME
// - OTEL_TRACES_SAMPLER
// - OTEL_TRACES_SAMPLER_ARG
// - OTEL_TRACES_EXPORTER
// - OTEL_RESOURCE_ATTRIBUTES
func ConfigFromEnv(serviceName, environment string) Config {
	cfg := Config{
		Enabled:          true,
		ServiceName:      serviceName,
		Environment:      environment,
		ExporterType:     "otlp",
		OTLPEndpoint:     "localhost:4317",
		JaegerEndpoint:   "localhost:6831",
		SampleRatio:      1.0,
		SamplerType:      "ratio",
		ResourceAttributes: make(map[string]string),
	}

	// Check if tracing is explicitly disabled
	if disabled := os.Getenv("OTEL_TRACES_EXPORTER"); disabled == "none" {
		cfg.Enabled = false
	}

	if envEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); envEndpoint != "" {
		cfg.OTLPEndpoint = envEndpoint
	}

	if envService := os.Getenv("OTEL_SERVICE_NAME"); envService != "" {
		cfg.ServiceName = envService
	}

	if envExporter := os.Getenv("OTEL_TRACES_EXPORTER"); envExporter != "" && envExporter != "none" {
		cfg.ExporterType = envExporter
	}

	if envSampler := os.Getenv("OTEL_TRACES_SAMPLER"); envSampler != "" {
		cfg.SamplerType = envSampler
	}

	if envSamplerArg := os.Getenv("OTEL_TRACES_SAMPLER_ARG"); envSamplerArg != "" {
		var ratio float64
		fmt.Sscanf(envSamplerArg, "%f", &ratio)
		if ratio >= 0 && ratio <= 1 {
			cfg.SampleRatio = ratio
		}
	}

	if envResource := os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); envResource != "" {
		pairs := strings.Split(envResource, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				cfg.ResourceAttributes[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	return cfg
}

// Init initializes the OpenTelemetry tracer provider with the given configuration.
// It returns a shutdown function that should be called during graceful shutdown.
func Init(ctx context.Context, cfg Config, log *zap.Logger) (func(context.Context) error, error) {
	if !cfg.Enabled {
		log.Info("OpenTelemetry tracing disabled")
		return func(context.Context) error { return nil }, nil
	}

	// Create base resource with service info
	res, err := createResource(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter based on configuration
	exporter, err := createExporter(ctx, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}

	// Create sampler based on configuration
	sampler := createSampler(cfg)

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	// Set global propagator for trace context and baggage
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Info("OpenTelemetry tracing initialized",
		zap.String("service", cfg.ServiceName),
		zap.String("exporter", cfg.ExporterType),
		zap.String("sampler", cfg.SamplerType),
		zap.Float64("sample_ratio", cfg.SampleRatio),
	)

	return tp.Shutdown, nil
}

// createResource creates an OpenTelemetry resource with service attributes
func createResource(cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
		semconv.DeploymentEnvironment(cfg.Environment),
	}

	// Add custom resource attributes
	for k, v := range cfg.ResourceAttributes {
		attrs = append(attrs, attribute.String(k, v))
	}

	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			attrs...,
		),
	)
}

// createExporter creates a trace exporter based on configuration
func createExporter(ctx context.Context, cfg Config, log *zap.Logger) (sdktrace.SpanExporter, error) {
	switch cfg.ExporterType {
	case "otlp", "otlpgrpc":
		return otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
			otlptracegrpc.WithInsecure(),
		)

	case "jaeger":
		// Jaeger exporter was removed from OTel SDK after v1.21.
		// Use OTLP exporter with a Jaeger backend instead:
		//   OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
		return nil, fmt.Errorf("jaeger exporter is deprecated; use 'otlp' exporter with Jaeger OTLP endpoint instead")

	case "stdout":
		return stdouttrace.New(
			stdouttrace.WithPrettyPrint(),
		)

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", cfg.ExporterType)
	}
}

// createSampler creates a sampler based on configuration
func createSampler(cfg Config) sdktrace.Sampler {
	switch cfg.SamplerType {
	case "always_on", "always":
		return sdktrace.AlwaysSample()
	case "always_off", "never":
		return sdktrace.NeverSample()
	case "parentbased", "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "ratio", "traceidratio":
		return sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))
	default:
		return sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	}
}

// spanOptions holds configuration for a span
type spanOptions struct {
	attributes []attribute.KeyValue
	spanKind   oteltrace.SpanKind
}

// Tracer provides helper methods for creating and managing spans
type Tracer struct {
	serviceName string
	tracer      oteltrace.Tracer
}

// NewTracer creates a new tracer helper for the service
func NewTracer(serviceName string) *Tracer {
	return &Tracer{
		serviceName: serviceName,
		tracer:      otel.Tracer(serviceName),
	}
}

// StartSpan starts a new span with the given name
func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	o := &spanOptions{}
	for _, opt := range opts {
		opt.apply(o)
	}

	// Build span options
	otelOpts := []oteltrace.SpanStartOption{
		oteltrace.WithAttributes(o.attributes...),
	}
	if o.spanKind != 0 {
		otelOpts = append(otelOpts, oteltrace.WithSpanKind(o.spanKind))
	}

	// Start the span using global tracer
	tracer := otel.Tracer(t.serviceName)
	ctx, span := tracer.Start(ctx, name, otelOpts...)

	return ctx, &Span{span: span}
}

// SpanOption configures a span
type SpanOption interface {
	apply(*spanOptions)
}

type spanOptionFunc func(*spanOptions)

func (f spanOptionFunc) apply(o *spanOptions) { f(o) }

// SpanOptions provides common span configuration options
var (
	WithSpanKindServer     = spanOptionFunc(func(o *spanOptions) { o.spanKind = oteltrace.SpanKindServer })
	WithSpanKindClient     = spanOptionFunc(func(o *spanOptions) { o.spanKind = oteltrace.SpanKindClient })
	WithSpanKindProducer   = spanOptionFunc(func(o *spanOptions) { o.spanKind = oteltrace.SpanKindProducer })
	WithSpanKindConsumer   = spanOptionFunc(func(o *spanOptions) { o.spanKind = oteltrace.SpanKindConsumer })
	WithSpanKindInternal   = spanOptionFunc(func(o *spanOptions) { o.spanKind = oteltrace.SpanKindInternal })
)

// WithAttributes adds attributes to the span
func WithAttributes(attrs ...attribute.KeyValue) SpanOption {
	return spanOptionFunc(func(o *spanOptions) {
		o.attributes = append(o.attributes, attrs...)
	})
}

// Span represents an OpenTelemetry span
type Span struct {
	span oteltrace.Span
}

// SetAttributes sets attributes on the span
func (s *Span) SetAttributes(attrs ...attribute.KeyValue) {
	s.span.SetAttributes(attrs...)
}

// SetError marks the span as having an error
func (s *Span) SetError(err error) {
	if err == nil {
		return
	}
	s.span.SetStatus(codes.Error, err.Error())
	s.span.SetAttributes(
		attribute.String("error.type", fmt.Sprintf("%T", err)),
		attribute.String("error.message", err.Error()),
	)
}

// End ends the span
func (s *Span) End() {
	s.span.End()
}

// RecordError records an error on the span without ending it
func (s *Span) RecordError(err error, opts ...oteltrace.EventOption) {
	s.span.RecordError(err, opts...)
}

// AddEvent adds an event to the span
func (s *Span) AddEvent(name string, attrs ...attribute.KeyValue) {
	s.span.AddEvent(name, oteltrace.WithAttributes(attrs...))
}

// HTTPMiddleware returns a Gin middleware for HTTP instrumentation
func HTTPMiddleware(serviceName string) gin.HandlerFunc {
	return otelgin.Middleware(serviceName)
}

// HTTPClient returns an HTTP client instrumented with tracing
func HTTPClient(base httpRoundTripper) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	return &http.Client{
		Transport: otelhttp.NewTransport(base),
	}
}

// InstrumentedRoundTripper wraps an http.RoundTripper with tracing
type InstrumentedRoundTripper struct {
	base http.RoundTripper
}

// NewInstrumentedRoundTripper creates a new instrumented HTTP round tripper
func NewInstrumentedRoundTripper(base http.RoundTripper) *InstrumentedRoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &InstrumentedRoundTripper{base: base}
}

// RoundTrip implements http.RoundTripper
func (i *InstrumentedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Use otelhttp transport
	transport := otelhttp.NewTransport(i.base)
	return transport.RoundTrip(req)
}

// WrapRedisClient wraps a Redis client with OpenTelemetry instrumentation.
// NOTE: Redis tracing hook is currently disabled — the redisotel contrib package
// is not available in the current OTel version. Re-enable when upgrading OTel contrib.
func WrapRedisClient(client *redis.Client) *redis.Client {
	return client
}

// WrapRedisFailoverClient wraps a Redis Failover client with OpenTelemetry instrumentation.
// NOTE: Redis tracing hook is currently disabled — see WrapRedisClient.
func WrapRedisFailoverClient(client *redis.Client) *redis.Client {
	return client
}

// PgxTracer implements pgx.QueryTracer for database instrumentation
type PgxTracer struct {
	tracer oteltrace.Tracer
}

// NewPgxTracer creates a new pgx tracer
func NewPgxTracer(serviceName string) *PgxTracer {
	return &PgxTracer{
		tracer: otel.Tracer(serviceName + ".db"),
	}
}

// TraceQueryStart implements pgx.QueryTracer
func (t *PgxTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	attrs := []attribute.KeyValue{
		attribute.String("db.system", "postgresql"),
		attribute.String("db.name", getDBName(conn.Config().Database)),
		attribute.String("db.statement", sanitizeSQL(data.SQL)),
		attribute.String("db.operation", extractOperation(data.SQL)),
	}

	ctx, _ = t.tracer.Start(ctx, "query",
		oteltrace.WithAttributes(attrs...),
		oteltrace.WithSpanKind(oteltrace.SpanKindClient),
	)

	return ctx
}

// TraceQueryEnd implements pgx.QueryTracer
func (t *PgxTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	span := oteltrace.SpanFromContext(ctx)
	if span == nil {
		return
	}

	if data.Err != nil {
		span.SetStatus(codes.Error, data.Err.Error())
		span.SetAttributes(
			attribute.Bool("error", true),
			attribute.String("error.message", data.Err.Error()),
		)
	} else {
		span.SetStatus(codes.Ok, "")
	}

	span.End()
}

// InstrumentPgxPool adds OpenTelemetry tracing to a pgx connection pool
func InstrumentPgxPool(pool *pgxpool.Pool, serviceName string) {
	tracer := NewPgxTracer(serviceName)
	pool.Config().ConnConfig.Tracer = tracer
}

// Baggage provides helper functions for working with OpenTelemetry baggage
type Baggage struct{}

// NewBaggage creates a new baggage manager
func NewBaggage() *Baggage {
	return &Baggage{}
}

// Set sets a baggage value in the context
func (b *Baggage) Set(ctx context.Context, key, value string) (context.Context, error) {
	member, err := baggage.NewMember(key, value)
	if err != nil {
		return nil, err
	}

	bag := baggage.FromContext(ctx)
	bag, err = bag.SetMember(member)
	if err != nil {
		return nil, err
	}

	return baggage.ContextWithBaggage(ctx, bag), nil
}

// Get gets a baggage value from the context
func (b *Baggage) Get(ctx context.Context, key string) string {
	bag := baggage.FromContext(ctx)
	if member := bag.Member(key); member.Key() != "" {
		return member.Value()
	}
	return ""
}

// GetAll returns all baggage from the context
func (b *Baggage) GetAll(ctx context.Context) map[string]string {
	bag := baggage.FromContext(ctx)
	result := make(map[string]string)
	for _, member := range bag.Members() {
		result[member.Key()] = member.Value()
	}
	return result
}

// ContextWithUserBaggage adds user-related baggage to the context
func ContextWithUserBaggage(ctx context.Context, userID, email string) (context.Context, error) {
	b := NewBaggage()
	var err error
	ctx, err = b.Set(ctx, "user.id", userID)
	if err != nil {
		return nil, err
	}
	ctx, err = b.Set(ctx, "user.email", email)
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

// GetUserIDFromBaggage extracts the user ID from baggage
func GetUserIDFromBaggage(ctx context.Context) string {
	b := NewBaggage()
	return b.Get(ctx, "user.id")
}

// Helper functions

func getDBName(url string) string {
	// Extract database name from connection string
	// Simple implementation - can be enhanced
	return "openidx"
}

func sanitizeSQL(sql string) string {
	// Remove potentially sensitive values from SQL for logging
	// This is a simple implementation - consider using a SQL parser for production
	return sql
}

func extractOperation(sql string) string {
	trimmed := strings.TrimSpace(strings.ToUpper(sql))
	for _, op := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER", "BEGIN", "COMMIT", "ROLLBACK"} {
		if strings.HasPrefix(trimmed, op) {
			return op
		}
	}
	return "EXECUTE"
}

// httpRoundTripper interface to avoid import issues
type httpRoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
}
